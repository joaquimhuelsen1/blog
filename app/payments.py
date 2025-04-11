import stripe
import os
from flask import Blueprint, request, redirect, url_for, current_app, session, flash, render_template
from flask_login import login_required, current_user

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
        return redirect(url_for('main.premium'))

    try:
        # Use current user's email if available, otherwise redirect to login
        customer_email = current_user.email
        if not customer_email:
             flash("Please log in to proceed with the checkout.", "warning")
             # Store intended destination
             session['next_url'] = url_for('main.premium') 
             return redirect(url_for('auth.login'))
             
        # Optional: Check if user already has a Stripe Customer ID
        # You might store this on your User model or retrieve it via webhook later
        # stripe_customer_id = current_user.stripe_customer_id 
        
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
            # Pass user ID to identify user when webhook is received
            client_reference_id=str(current_user.id),
            customer_email=customer_email, # Pre-fill email
            # If you already have a Stripe Customer ID for the user, pass it here:
            # customer=stripe_customer_id,
            # Allow promotion codes
            allow_promotion_codes=True,
        )
        return redirect(checkout_session.url, code=303)

    except Exception as e:
        current_app.logger.error(f"Error creating Stripe Checkout session: {str(e)}")
        flash(f"Could not initiate checkout: {str(e)}", "danger")
        return redirect(url_for('main.premium'))

@payments_bp.route('/checkout-success')
def checkout_success():
    """Page shown after successful checkout. Stripe webhook handles fulfillment."""
    # session_id = request.args.get('session_id')
    # You could potentially retrieve the session here for display purposes, 
    # but rely on the webhook for actual fulfillment.
    flash("Payment successful! Your premium access is being processed.", "success")
    return render_template('payments/checkout_success.html')

@payments_bp.route('/checkout-cancel')
def checkout_cancel():
    """Page shown if the user cancels the checkout process."""
    flash("Checkout canceled. You can try again anytime.", "info")
    return render_template('payments/checkout_cancel.html')


@payments_bp.route('/stripe-webhook', methods=['POST'])
def stripe_webhook():
    """Handle incoming webhooks from Stripe."""
    stripe.api_key = os.environ.get('STRIPE_SECRET_KEY')
    webhook_secret = os.environ.get('STRIPE_WEBHOOK_SECRET')
    n8n_webhook_url = os.environ.get('N8N_STRIPE_UPDATE_WEBHOOK')
    
    if not webhook_secret or not n8n_webhook_url:
         current_app.logger.error("Stripe webhook secret or N8N update URL not configured.")
         return "Webhook configuration error", 500
         
    payload = request.data
    sig_header = request.headers.get('Stripe-Signature')
    event = None

    try:
        event = stripe.Webhook.construct_event(
            payload, sig_header, webhook_secret
        )
        current_app.logger.info(f"Received Stripe event: {event['type']}")
    except ValueError as e:
        # Invalid payload
        current_app.logger.error(f"Invalid Stripe webhook payload: {e}")
        return "Invalid payload", 400
    except stripe.error.SignatureVerificationError as e:
        # Invalid signature
        current_app.logger.error(f"Invalid Stripe webhook signature: {e}")
        return "Invalid signature", 400
    except Exception as e:
        current_app.logger.error(f"Error constructing Stripe event: {e}")
        return "Webhook error", 500

    # Handle the checkout.session.completed event
    if event['type'] == 'checkout.session.completed':
        session = event['data']['object']
        client_reference_id = session.get('client_reference_id') # User ID from Flask
        stripe_customer_id = session.get('customer')
        stripe_subscription_id = session.get('subscription')
        customer_email = session.get('customer_details', {}).get('email')

        if not client_reference_id or not stripe_customer_id or not stripe_subscription_id:
            current_app.logger.error(f"Missing data in checkout.session.completed event: {session}")
            return "Missing data in event", 400
            
        current_app.logger.info(f"Checkout completed for user {client_reference_id}. Customer: {stripe_customer_id}, Sub: {stripe_subscription_id}")

        # --- Call N8N Webhook to Update User --- 
        n8n_payload = {
            'event': 'stripe_checkout_completed',
            'user_id': client_reference_id,
            'stripe_customer_id': stripe_customer_id,
            'stripe_subscription_id': stripe_subscription_id,
            'email': customer_email # Include email just in case
        }
        
        try:
            import requests
            response = requests.post(n8n_webhook_url, json=n8n_payload, timeout=15)
            response.raise_for_status() # Raise HTTPError for bad responses (4xx or 5xx)
            current_app.logger.info(f"N8N update webhook called successfully for user {client_reference_id}. Status: {response.status_code}")
        except requests.RequestException as e:
            current_app.logger.error(f"Error calling N8N update webhook for user {client_reference_id}: {e}")
            # Decide if you want to retry or just log. Returning 500 might cause Stripe to retry.
            return "Failed to call update webhook", 500
        # -----------------------------------------

    # Handle other event types as needed (e.g., subscription updates/cancellations)
    # elif event['type'] == 'customer.subscription.deleted':
    #     # Handle subscription cancellation
    #     pass
    # elif event['type'] == 'customer.subscription.updated':
    #     # Handle subscription changes (e.g., plan change, status change)
    #     pass
    else:
        current_app.logger.info(f"Unhandled Stripe event type: {event['type']}")

    return "Success", 200


@payments_bp.route('/customer-portal', methods=['POST'])
@login_required
def customer_portal():
    """Create a Stripe Billing Portal session for the user."""
    stripe.api_key = os.environ.get('STRIPE_SECRET_KEY')
    
    if not stripe.api_key:
        current_app.logger.error("Stripe keys not configured for portal.")
        flash("System configuration error. Please contact support.", "danger")
        return redirect(url_for('auth.profile'))

    # Retrieve the Stripe Customer ID stored for the user
    # This needs to be fetched from your user data (which should be updated by the N8N webhook)
    stripe_customer_id = None 
    try:
        # --- HOW TO GET STRIPE CUSTOMER ID? --- 
        # Option 1: Directly from current_user if you update the User object
        # stripe_customer_id = current_user.stripe_customer_id 
        
        # Option 2: From session if stored there after login/webhook update
        user_data = session.get('user_data')
        if user_data:
             stripe_customer_id = user_data.get('stripe_customer_id') # Assuming N8N adds this field

        if not stripe_customer_id:
            current_app.logger.warning(f"User {current_user.id} is premium but has no Stripe Customer ID stored.")
            flash("Could not find your billing information. Please contact support.", "warning")
            return redirect(url_for('auth.profile'))
            
        # ------------------------------------------
        
        # Generate the portal session
        portal_session = stripe.billing_portal.Session.create(
            customer=stripe_customer_id,
            return_url=url_for('auth.profile', _external=True),
        )
        return redirect(portal_session.url, code=303)
        
    except Exception as e:
        current_app.logger.error(f"Error creating Stripe Customer Portal session: {str(e)}")
        flash(f"Could not open billing portal: {str(e)}", "danger")
        return redirect(url_for('auth.profile')) 