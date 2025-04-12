from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, BooleanField, SubmitField, TextAreaField, IntegerField, DateTimeField, FileField, SelectField, RadioField, HiddenField
from wtforms.validators import DataRequired, Email, EqualTo, Length, ValidationError, URL, Optional, NumberRange
from app.models import User
from datetime import datetime

class LoginForm(FlaskForm):
    # Desabilitar CSRF no formulário
    class Meta:
        csrf = False
        
    email = StringField('Email', validators=[DataRequired(), Email()])
    submit = SubmitField('Send Login Code')

class VerifyLoginForm(FlaskForm):
    otp = StringField('Login Code', validators=[
        DataRequired(), 
        Length(min=6, max=6, message='The code must be 6 digits long.')
    ])
    submit = SubmitField('Verify and Log In')

class RegistrationForm(FlaskForm):
    email = StringField('Email', validators=[DataRequired(), Email()])
    submit = SubmitField('Send Verification Code')

class PostForm(FlaskForm):
    title = StringField('Title', validators=[DataRequired(), Length(max=100)])
    summary = TextAreaField('Summary', validators=[DataRequired(), Length(max=200)])
    content = TextAreaField('Content', validators=[DataRequired()])
    image = FileField('Image', validators=[Optional()])
    image_url = StringField('Image URL', validators=[Optional(), URL()], description="Enter a URL for the post's cover image. If left empty, a placeholder will be used.")
    reading_time = IntegerField('Reading Time (minutes)', validators=[Optional(), NumberRange(min=1, max=60)], description="Estimated reading time in minutes. Leave empty for automatic calculation.")
    created_at = DateTimeField('Publication Date', format='%Y-%m-%dT%H:%M', validators=[Optional()], default=datetime.utcnow, description="Publication date and time. Leave empty to use current date.")
    status = SelectField('Status', choices=[('agendado', 'Agendado'), ('postar agora', 'Postar Agora')], default='agendado', description="Define if the post will be scheduled or published immediately.")
    type_content = SelectField('Tipo de Conteúdo', choices=[
        ('winning back', 'Winning Back'), 
        ('stay connected', 'Stay Connected'), 
        ('overcoming', 'Overcoming'), 
        ('case analysis', 'Case Analysis')
    ], validators=[Optional()], description="Content category.")
    notion_url = StringField('Notion URL', validators=[Optional(), URL()], description="Link to related document in Notion.")
    premium_only = BooleanField('Premium Only', default=False, description="If checked, only premium users will be able to access this post.")
    submit = SubmitField('Save Post')

    def validate_image(self, field):
        if field.data:
            filename = field.data.filename.lower()
            if not filename.endswith(('.jpg', '.jpeg', '.png', '.gif')):
                raise ValidationError('Only image files (jpg, jpeg, png, gif) are allowed.')

class UserUpdateForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired(), Length(min=2, max=20)])
    email = StringField('Email', validators=[DataRequired(), Email()])
    age = IntegerField('Age', validators=[Optional(), NumberRange(min=18, max=120)])
    is_premium = BooleanField('Premium User')
    is_admin = BooleanField('Admin User')
    submit = SubmitField('Update User')

class ProfileUpdateForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired(), Length(min=2, max=20)], render_kw={'readonly': True})
    email = StringField('Email', validators=[DataRequired(), Email()], render_kw={'readonly': True})
    age = IntegerField('Age', validators=[Optional()])
    submit = SubmitField('Update Profile')
    
    def __init__(self, original_username=None, original_email=None, *args, **kwargs):
        super(ProfileUpdateForm, self).__init__(*args, **kwargs)
        self.original_username = original_username
        self.original_email = original_email
    
    # Username and Email validation is skipped since the fields are readonly

class CommentForm(FlaskForm):
    content = TextAreaField('Your Comment', validators=[
        DataRequired(message="Comment cannot be empty."), 
        Length(min=3, max=2000, message="Comment must be between 3 and 2000 characters.")
    ], render_kw={"rows": 4, "placeholder": "Write your comment here..."})
    submit = SubmitField('Post Comment')

class ChatMessageForm(FlaskForm):
    message = TextAreaField('Your Message', validators=[DataRequired(), Length(min=2, max=1000)])
    submit = SubmitField('Send')

class PasswordChangeForm(FlaskForm):
    current_password = PasswordField('Current Password', validators=[DataRequired()])
    new_password = PasswordField('New Password', validators=[DataRequired(), Length(min=6)])
    confirm_password = PasswordField('Confirm New Password', validators=[DataRequired(), EqualTo('new_password', message='Passwords must match.')])
    submit = SubmitField('Change Password')

class UserProfileForm(FlaskForm):
    email = StringField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('New Password', validators=[Optional(), Length(min=6)])
    confirm_password = PasswordField('Confirm New Password', validators=[Optional(), EqualTo('password', message='Passwords must match')])
    age = IntegerField('Age', validators=[Optional(), NumberRange(min=18, max=120)], description="Optional. You can leave this field blank.")
    submit = SubmitField('Update Profile')

class VerifyOtpForm(FlaskForm):
    otp = StringField('Code 6 digits', validators=[
        DataRequired(), 
        Length(min=6, max=6, message='The OTP code must be 6 digits long.')
    ])
    username = StringField('Username', validators=[DataRequired(), Length(min=2, max=20)])
    submit = SubmitField('Verify and Register')
    # Adicionar validações se o webhook não as fizer (ex: username já existe)
    # def validate_username(self, username):
    #     # Lógica para verificar via webhook se necessário
    #     pass 

class MemberConsultingForm(FlaskForm):
    purchase_email = StringField(
        'Your purchase email', 
        validators=[DataRequired(message="Purchase email is required."), Email()]
    )
    full_name = StringField(
        '1. Your full name', 
        validators=[DataRequired(message="Your full name is required.")]
    )
    age = IntegerField(
        '2. Your age', 
        validators=[DataRequired(message="Your age is required."), NumberRange(min=18, max=120)]
    )
    partner_name = StringField(
        "3. Your ex/current partner's name", 
        validators=[DataRequired(message="Partner's name is required.")]
    )
    partner_age = IntegerField(
        "4. Your ex/current partner's age", 
        validators=[DataRequired(message="Partner's age is required."), NumberRange(min=18, max=120)]
    )
    relationship_length = TextAreaField(
        '5. How long were you in a relationship?', 
        validators=[DataRequired(message="Relationship duration description is required.")],
        render_kw={"rows": 3}
    )
    breakup_reason = TextAreaField(
        '6. What was the main reason for the breakup?',
        validators=[DataRequired(message="Breakup reason is required.")],
        render_kw={"rows": 5}
    )
    contact_method = RadioField(
        "7. What's the best way for us to contact you?",
        choices=[
            ('Telegram', 'Telegram'), 
            ('iPhone Messages', 'iPhone Messages'), 
            ('Email', 'Email')
        ],
        validators=[DataRequired(message="Please choose a contact method.")]
    )
    contact_info = TextAreaField(
        '8. Add your contact information based on your chosen method:',
        description='Ideal response format\n\n<b>Telegram:</b> Name (Join the Telegram group and send me a private message for a quicker response)\n<b>iPhone Messages:</b> Number (USA only)\n<b>Email:</b> youremail@email.com',
        validators=[DataRequired(message="Contact information is required.")],
        render_kw={"rows": 3}
    )
    submit = SubmitField('Submit Information')
    
    # --- ADD UTM Hidden Fields ---
    utm_source = HiddenField('utm_source')
    utm_medium = HiddenField('utm_medium')
    utm_campaign = HiddenField('utm_campaign')
    utm_term = HiddenField('utm_term')
    utm_content = HiddenField('utm_content') 