import stripe
import os
import requests
from flask import Blueprint, request, redirect, url_for, current_app, session, flash, render_template, jsonify
from flask_login import login_required, current_user
from app import csrf

payments_bp = Blueprint('payments', __name__)

@payments_bp.route('/create-checkout-session', methods=['POST'])
@login_required
def create_checkout_session():
    """Create a Stripe Checkout session for the premium plan."""
    stripe.api_key = os.environ.get('STRIPE_SECRET_KEY')
    price_id = os.environ.get('STRIPE_PREMIUM_PRICE_ID')
    
    if not stripe.api_key or not price_id:
        current_app.logger.error("Stripe keys or Price ID not configured.")
        flash("Payment system configuration error. Please contact support.", "danger")
        return redirect(url_for('main.premium_subscription'))

    try:
        customer_email = current_user.email
        if not customer_email:
             flash("Please log in to proceed with the checkout.", "warning")
             session['next_url'] = url_for('main.premium_subscription') 
             return redirect(url_for('auth.login'))
             
        checkout_session = stripe.checkout.Session.create(
            line_items=[
                {
                    'price': price_id,
                    'quantity': 1,
                },
            ],
            mode='subscription',
            # Add trial period data
            subscription_data={
                'trial_period_days': 14,
            },
            success_url=url_for('payments.checkout_success', _external=True) + '?session_id={CHECKOUT_SESSION_ID}',
            cancel_url=url_for('payments.checkout_cancel', _external=True),
            client_reference_id=str(current_user.id),
            customer_email=customer_email, 
            allow_promotion_codes=True,
        )
        return redirect(checkout_session.url, code=303)

    except Exception as e:
        current_app.logger.error(f"Error creating Stripe Checkout session: {str(e)}")
        flash(f"Could not initiate checkout: {str(e)}", "danger")
        return redirect(url_for('main.premium_subscription'))

@payments_bp.route('/checkout-success')
def checkout_success():
    """Page shown after successful checkout. Stripe webhook handles fulfillment."""
    flash("Payment successful! Your premium access is being processed.", "success")
    return render_template('payments/checkout_success.html')

@payments_bp.route('/checkout-cancel')
def checkout_cancel():
    """Page shown if the user cancels the checkout process."""
    flash("Checkout canceled. You can try again anytime.", "info")
    return render_template('payments/checkout_cancel.html')


@payments_bp.route('/stripe-webhook', methods=['POST'])
@csrf.exempt
def stripe_webhook():
    """Handle incoming webhooks from Stripe."""
    stripe.api_key = os.environ.get('STRIPE_SECRET_KEY')
    webhook_secret = os.environ.get('STRIPE_WEBHOOK_SECRET')
    n8n_webhook_url = os.environ.get('N8N_STRIPE_UPDATE_WEBHOOK')
    
    if not webhook_secret or not n8n_webhook_url:
         current_app.logger.error("Stripe webhook secret or N8N update URL not configured.")
         return jsonify(error="Webhook configuration error on server"), 500
         
    payload = request.data
    sig_header = request.headers.get('Stripe-Signature')
    event = None

    try:
        event = stripe.Webhook.construct_event(
            payload, sig_header, webhook_secret
        )
        current_app.logger.info(f"Received Stripe event: {event['type']} (ID: {event['id']})")
    except ValueError as e:
        current_app.logger.error(f"Invalid Stripe webhook payload: {e}")
        return jsonify(error="Invalid payload"), 400
    except stripe.error.SignatureVerificationError as e:
        current_app.logger.error(f"Invalid Stripe webhook signature: {e}")
        return jsonify(error="Invalid signature"), 400
    except Exception as e:
        current_app.logger.error(f"Error constructing Stripe event: {e}")
        return jsonify(error="Webhook error during event construction"), 500

    # --- Default N8N payload structure ---
    n8n_update_successful = False # Flag to track if N8N update worked

    # --- Handle specific event types ---
    try:
        if event['type'] == 'checkout.session.completed':
            session_data = event['data']['object']
            client_reference_id = session_data.get('client_reference_id') # User ID from Flask
            stripe_customer_id = session_data.get('customer')
            stripe_subscription_id = session_data.get('subscription')
            customer_email = session_data.get('customer_details', {}).get('email')

            if not client_reference_id or not stripe_customer_id or not stripe_subscription_id:
                current_app.logger.error(f"Missing data in checkout.session.completed event: {session_data}")
                return jsonify(error="Missing data in event"), 400
            
            current_app.logger.info(f"Processing checkout.session.completed for user {client_reference_id}. Customer: {stripe_customer_id}, Sub: {stripe_subscription_id}")

            # Prepare specific N8N payload for this event
            n8n_payload = {
                'event': 'stripe_checkout_completed', # Specific event indicator for N8N
                'user_id': client_reference_id,
                'stripe_customer_id': stripe_customer_id,
                'stripe_subscription_id': stripe_subscription_id,
                'email': customer_email,
                'stripe_event_id': event['id'] # Include Stripe event ID for tracing
            }
            
            # --- Call N8N Webhook Synchronously ---
            # Wrap N8N call in its own try/except for network errors
            try:
                response_n8n = requests.post(n8n_webhook_url, json=n8n_payload, timeout=10) 
                response_n8n.raise_for_status() 
                current_app.logger.info(f"N8N update webhook called for checkout completed (User {client_reference_id}). Status: {response_n8n.status_code}")
                
                # --- Process N8N Response (Log & Check Success, NO Session Update Here) ---
                try:
                    n8n_response_data = response_n8n.json()
                    current_app.logger.info(f"N8N response data: {n8n_response_data}")
                    # --- CORRECTED CHECK: Expecting a dictionary directly --- 
                    if response_n8n.status_code == 200 and isinstance(n8n_response_data, dict) and n8n_response_data.get('id') == client_reference_id:
                        current_app.logger.info(f"N8N successfully processed update for user {client_reference_id}.")
                        n8n_update_successful = True
                        # Log intent but acknowledge limitation
                        current_app.logger.info(f"N8N success confirmed for user {client_reference_id}. User data updated in DB. Session will update on next user request.")
                    else:
                        current_app.logger.error(f"N8N processing failed or returned unexpected data for user {client_reference_id}. Status: {response_n8n.status_code}, Response: {response_n8n.text[:200]}")
                        n8n_update_successful = False
                except Exception as e_n8n_resp:
                    current_app.logger.error(f"Error processing N8N response for user {client_reference_id}: {e_n8n_resp}")
                    n8n_update_successful = False
                # --- End N8N Response Processing ---

            except requests.RequestException as e_n8n_req:
                # Handle network errors calling N8N specifically here
                current_app.logger.error(f"Network error calling N8N update webhook for user {client_reference_id}: {e_n8n_req}")
                n8n_update_successful = False # Mark as failed
            # --- End N8N Call --- 

            # Return 500 to Stripe only if N8N call failed critically
            if not n8n_update_successful:
                 return jsonify(error="Failed to process update via N8N"), 500

        elif event['type'] == 'customer.subscription.deleted':
            sub_data = event['data']['object']
            stripe_customer_id = sub_data.get('customer')
            stripe_subscription_id = sub_data.get('id')
            current_app.logger.info(f"Processing customer.subscription.deleted for Customer: {stripe_customer_id}, Sub: {stripe_subscription_id}")
            
            # Prepare N8N payload
            n8n_payload = {
                'event': 'stripe_subscription_deleted',
                'stripe_customer_id': stripe_customer_id,
                'stripe_subscription_id': stripe_subscription_id,
                'stripe_event_id': event['id']
            }
            # Call N8N (fire and forget is safer here)
            requests.post(n8n_webhook_url, json=n8n_payload, timeout=5) 
            # Don't wait or check response strictly, N8N should handle idempotency
            current_app.logger.info(f"N8N update webhook called for subscription deleted (Customer {stripe_customer_id}).")
            n8n_update_successful = True # Assume N8N will handle it

        elif event['type'] == 'customer.subscription.updated':
            sub_data = event['data']['object']
            stripe_customer_id = sub_data.get('customer')
            stripe_subscription_id = sub_data.get('id')
            status = sub_data.get('status') # e.g., 'active', 'past_due', 'canceled'
            current_app.logger.info(f"Processing customer.subscription.updated for Customer: {stripe_customer_id}, Sub: {stripe_subscription_id}, Status: {status}")

            # Prepare N8N payload
            n8n_payload = {
                'event': 'stripe_subscription_updated',
                'stripe_customer_id': stripe_customer_id,
                'stripe_subscription_id': stripe_subscription_id,
                'subscription_status': status,
                'stripe_event_id': event['id'],
                'full_subscription_data': sub_data # Send full data for N8N logic
            }
            # Call N8N (fire and forget)
            requests.post(n8n_webhook_url, json=n8n_payload, timeout=5)
            current_app.logger.info(f"N8N update webhook called for subscription updated (Customer {stripe_customer_id}).")
            n8n_update_successful = True # Assume N8N will handle it
            
        elif event['type'] == 'invoice.payment_failed':
            invoice_data = event['data']['object']
            stripe_customer_id = invoice_data.get('customer')
            invoice_id = invoice_data.get('id')
            current_app.logger.warning(f"Processing invoice.payment_failed for Customer: {stripe_customer_id}, Invoice: {invoice_id}")

            # Prepare N8N payload (e.g., to trigger a notification)
            n8n_payload = {
                'event': 'stripe_payment_failed',
                'stripe_customer_id': stripe_customer_id,
                'invoice_id': invoice_id,
                'stripe_event_id': event['id'],
                'full_invoice_data': invoice_data
            }
            # Call N8N (fire and forget)
            requests.post(n8n_webhook_url, json=n8n_payload, timeout=5)
            current_app.logger.info(f"N8N notification webhook called for payment failed (Customer {stripe_customer_id}).")
            n8n_update_successful = True # Assume N8N will handle it

        else:
            current_app.logger.info(f"Unhandled Stripe event type received: {event['type']}")
            # Return 200 for unhandled events we don't care about
            return jsonify(status="Unhandled event type"), 200

        # Return 200 OK to Stripe if N8N call was attempted (or successful for completed event)
        # If N8N call failed critically for completed event, return 500 to retry
        if event['type'] == 'checkout.session.completed' and not n8n_update_successful:
             return jsonify(error="Failed to process update via N8N"), 500
        else:
             return jsonify(status="Webhook processed"), 200

    except requests.RequestException as e:
        # Handle network errors calling N8N specifically for checkout.session.completed
        if event and event['type'] == 'checkout.session.completed':
             client_ref_id = event.get('data', {}).get('object', {}).get('client_reference_id', 'UNKNOWN')
             current_app.logger.error(f"Network error calling N8N update webhook for user {client_ref_id}: {e}")
             # Return 500 to make Stripe retry
             return jsonify(error="Network error calling backend update service"), 500
        else:
             # For other events where N8N call is fire-and-forget, just log and return 200
             current_app.logger.error(f"Network error calling N8N (event: {event['type'] if event else 'Unknown'}): {e}")
             return jsonify(status="Webhook processed despite N8N call error"), 200

    except Exception as e:
        # Catch-all for other unexpected errors during processing
        event_type = event['type'] if event else 'Unknown'
        current_app.logger.error(f"Unexpected error processing Stripe event {event_type}: {e}")
        current_app.logger.error(traceback.format_exc())
        # Return 500 to make Stripe retry potentially recoverable errors
        return jsonify(error="Internal server error processing webhook"), 500


@payments_bp.route('/customer-portal', methods=['POST'])
@login_required
def customer_portal():
    """Calls N8N webhook to generate a Stripe Billing Portal session URL."""
    n8n_webhook_url = os.environ.get('N8N_STRIPE_UPDATE_WEBHOOK') # Use the same webhook URL
    
    if not n8n_webhook_url:
        current_app.logger.error("N8N update URL not configured for portal.")
        flash("System configuration error. Please contact support.", "danger")
        return redirect(url_for('auth.profile'))

    stripe_customer_id = None
    try:
        # Get Stripe Customer ID from session (MUST be saved by N8N after checkout)
        user_data = session.get('user_data')
        if user_data:
             stripe_customer_id = user_data.get('stripe_customer_id') 

        if not stripe_customer_id:
            current_app.logger.warning(f"User {current_user.id} ({current_user.email}) trying to access portal but has no Stripe Customer ID stored.")
            is_premium = (user_data and user_data.get('is_premium')) or current_user.is_premium
            if is_premium:
                 flash("Your billing information is not yet synced. Please try again in a few moments or contact support.", "warning")
            else:
                 flash("Billing portal is only available for Premium subscribers.", "info")
            return redirect(url_for('auth.profile'))

        # --- Call N8N to generate portal link --- 
        n8n_payload = {
            'event': 'generate_portal_link', # New event type for N8N
            'stripe_customer_id': stripe_customer_id,
            'return_url': url_for('auth.profile', _external=True) # Provide return URL to N8N
        }
        current_app.logger.info(f"Requesting N8N to generate portal link for Customer ID: {stripe_customer_id}")
        
        # Wrap N8N call in try/except
        try:
            response_n8n = requests.post(n8n_webhook_url, json=n8n_payload, timeout=10)
            response_n8n.raise_for_status()
            n8n_response_data = response_n8n.json()
            
            # Expect N8N to return { "success": true, "portal_url": "..." }
            if response_n8n.status_code == 200 and n8n_response_data.get('success') and n8n_response_data.get('portal_url'):
                portal_url = n8n_response_data['portal_url']
                current_app.logger.info(f"N8N returned portal URL: {portal_url}")
                return redirect(portal_url, code=303)
            else:
                current_app.logger.error(f"N8N failed to generate portal link or returned invalid data. Status: {response_n8n.status_code}, Response: {response_n8n.text[:200]}")
                flash("Could not generate billing portal link. Please try again or contact support.", "danger")
                return redirect(url_for('auth.profile'))

        except requests.RequestException as e_n8n_req:
            current_app.logger.error(f"Network error calling N8N for portal link: {e_n8n_req}")
            flash("Network error accessing billing portal. Please try again.", "danger")
            return redirect(url_for('auth.profile'))
        # ----------------------------------------- 

    except Exception as e:
        current_app.logger.error(f"Unexpected error creating Customer Portal session via N8N for user {current_user.id}: {str(e)}")
        flash(f"Could not open billing portal: An unexpected error occurred.", "danger")
        return redirect(url_for('auth.profile')) 