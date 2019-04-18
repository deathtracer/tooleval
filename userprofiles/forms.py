from django import forms
from django.contrib.auth.forms import UserCreationForm
from django.contrib.auth.models import User
from .models import UserProfile
from django.contrib.auth.forms import PasswordResetForm
from django.contrib.auth.models import User
from django.contrib import messages
from django.http import HttpResponseRedirect
from django.urls import reverse
from django.core.exceptions import ValidationError



class UserForm(forms.ModelForm):
	password = forms.CharField(widget=forms.PasswordInput())

	class Meta():
		model = User
		fields = ['username', 'password','email',]
		widgets = { 'username': forms.TextInput(attrs={'placeholder': 'Username'}),
					'password': forms.PasswordInput(attrs={'placeholder': 'Password', 'class': 'form-control' }),
					'email': forms.TextInput(attrs={'placeholder': 'Email'}),
		}


class UserProfileForm(forms.ModelForm):
	phone_number = forms.RegexField(regex=r'^\d{9,10}$')
	class Meta():
		model = UserProfile
		fields = ['institution', 'course', 'phone_number',]
		widgets = {
					'institution': forms.TextInput(attrs={'placeholder': 'Institute', 'class': 'form-control' }),
					'course': forms.TextInput(attrs={'placeholder': 'Course', 'class': 'form-control' }),
					'phone_number': forms.TextInput(attrs={'placeholder': 'Phone Number', 'class': 'form-control'}),
		}

class UserProfileEditForm(forms.ModelForm):
	class Meta():
		model = UserProfile
		fields = ['name', 'email', 'institution', 'course', 'graduation_year', 'bio', 'phone_number',]
		widgets = {
					'institution': forms.TextInput(attrs={'placeholder': 'Institute', 'class': 'form-control' }),
					'course': forms.TextInput(attrs={'placeholder': 'Course', 'class': 'form-control' }),
					'name': forms.TextInput(attrs={'placeholder': 'Your Name', 'class': 'form-control' }),
					'graduation_year': forms.Select(attrs={'class': 'form-control'}),
					'bio': forms.TextInput(attrs={'placeholder': 'About yourself', 'class': 'form-control' }),
					'email': forms.TextInput(attrs={'placeholder': 'Email', 'class': 'form-control' }),
					'phone_number': forms.TextInput(attrs={'placeholder': 'Phone Number', 'class': 'form-control'}),
		}

