from flask_wtf import FlaskForm
from werkzeug.security import check_password_hash
from wtforms import StringField, PasswordField, SubmitField
from wtforms import validators, fields, form
from wtforms.validators import DataRequired, Email, EqualTo, Length

from database.models import db, User


class LoginForm(form.Form):
    login = fields.StringField(validators=[validators.InputRequired()])
    password = fields.PasswordField(validators=[validators.InputRequired()])

    def validate_login(self, field):
        user = self.get_user()

        if user is None:
            raise validators.ValidationError('Вы не зарегистрированы')

        if not check_password_hash(user.password, self.password.data):
            raise validators.ValidationError('Неправильный Пароль')

        if user.is_admin is False:
            raise validators.ValidationError('Вы не администратор')

    def get_user(self):
        return db.session.query(User).filter_by(username=self.login.data).first()


class ChangePasswordForm(FlaskForm):
    current_password = PasswordField('Текущий пароль', validators=[DataRequired()])
    new_password = PasswordField('Новый пароль', validators=[DataRequired(), Length(min=6)])
    confirm_password = PasswordField('Подтвердите пароль', validators=[DataRequired(), EqualTo('new_password')])
    submit = SubmitField('Сменить пароль')


class ChangeEmailForm(FlaskForm):
    new_email = StringField('Новый Email', validators=[DataRequired(), Email()])
    submit = SubmitField('Сменить Email')


class BlogPostForm(FlaskForm):
    title = StringField('Title', validators=[DataRequired(), Length(max=100)])
    content = TextAreaField('Content', validators=[DataRequired()])
    submit = SubmitField('Submit')


class ProjectForm(FlaskForm):
    name = StringField('Name', validators=[DataRequired(), Length(max=100)])
    image_url = StringField('Image URL', validators=[DataRequired(), Length(max=200)])
    url = StringField('URL', validators=[DataRequired(), Length(max=200)])
    submit = SubmitField('Submit')


class NavigationLinkForm(FlaskForm):
    title = StringField('Title', validators=[DataRequired(), Length(max=100)])
    url = StringField('URL', validators=[DataRequired(), Length(max=200)])
    submit = SubmitField('Submit')


class MusicReleaseForm(FlaskForm):
    title = StringField('Title', validators=[DataRequired(), Length(max=100)])
    release_url = StringField('Release URL', validators=[DataRequired(), Length(max=200)])
    submit = SubmitField('Submit')


class MusicDemoForm(FlaskForm):
    title = StringField('Title', validators=[DataRequired(), Length(max=100)])
    file = FileField('File', validators=[DataRequired()])
    submit = SubmitField('Upload')
