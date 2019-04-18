from builtins import print

try:
	import urllib2
except:
	import urllib.request as urllib2
import urllib
import json

from django.shortcuts import render, redirect, get_object_or_404
from django.contrib.auth.decorators import login_required
from django.contrib.auth import authenticate, login ,logout
from django.contrib.auth.models import User
from django.http import HttpResponseRedirect, HttpResponse, Http404
from django.urls import reverse, reverse_lazy
from django.core.exceptions import ValidationError, PermissionDenied
from django.contrib.auth.mixins import LoginRequiredMixin
from django.utils import timezone
from django.conf import settings
from django.contrib import messages
from django.contrib.sites.shortcuts import get_current_site
from django.utils.encoding import force_bytes, force_text
from django.utils.http import urlsafe_base64_encode, urlsafe_base64_decode
from django.template.loader import render_to_string
from django.core.mail import EmailMessage
from datetime import datetime
from django.contrib.auth.decorators import login_required
from .forms import UserForm, UserProfileForm, UserProfileEditForm
from .tokens import account_activation_token
from .models import Event, UserProfile
from django.contrib.auth import update_session_auth_hash
from django.contrib.auth.forms import PasswordChangeForm



# Create your views here.

def index(request):
	return render(request, "index.html")

def login_view(request):
	if request.method == 'POST':

		username = request.POST['username']
		password = request.POST['password']

		user = authenticate(request, username=username, password=password)

		if user is not None:

			if user.is_active:
				login(request, user)
				profile = UserProfile.objects.get(user=user)
				profile.last_login_time = datetime.now()
				profile.ip_address = request.META.get('REMOTE_ADDR')
				profile.user_agent = request.META.get('HTTP_USER_AGENT')
				profile.save()

				if 'next' in request.POST:
					return redirect(request.POST.get('next'))

				else:
					return HttpResponseRedirect(reverse("userDash"))

			else:
				return HttpResponseRedirect(reverse("login"))

		else:
			return render(request, "login.html", {"message":"Invalid credentials!"})

	else:
		if request.user.is_authenticated:
			return HttpResponseRedirect(reverse("userDash"))
		else:
			return render(request, 'login.html',{})


@login_required
def change_password(request):
    if request.method == 'POST':
        form = PasswordChangeForm(request.user, request.POST)
        if form.is_valid():
            user = form.save()
            update_session_auth_hash(request, user)  # Important!
            messages.success(request, 'Your password was successfully updated!')
            return redirect('userDash')
        else:
            messages.error(request, 'Please correct the error below.')
    else:
        form = PasswordChangeForm(request.user)
    return render(request, 'registration/change_password.html', {'form': form})

@login_required
def logout_view(request):
	logout(request)
	return render(request, "logout.html", {"message":"Logged Out successfully!"})

@login_required
def userDash(request):
	user = UserProfile.objects.get(user=request.user)
	context = {
		"userp" : user,
		"events" : Event.objects.all(),
		"registered_events": user.events_registered.all(),
	}
	return render(request, "userdash.html", context)


def viewEvent(request, event_id):
	try:
		event = Event.objects.get(pk=event_id)
			
	except Event.DoesNotExist:
		raise Http404('Event does not exist!')
		
	return render(request, "viewEvent.html", {"anEvent" : event})


@login_required
def registerForEvent(request, event_id1):

	try:
		event = Event.objects.get(pk=event_id1)
		user = UserProfile.objects.get(user=request.user)
	except Event.DoesNotExist:
		raise Http404('Event does not exist')

	user.events_registered.add(event)
	return HttpResponseRedirect(reverse("userDash"))

	#return render(request, "viewEvent.html", context)

@login_required
def unregisterForEvent(request, event_id2):

	try:
		event = Event.objects.get(pk=event_id2)
		user = UserProfile.objects.get(user=request.user)
	except Event.DoesNotExist:
		raise Http404('Event does not exist')

	user.events_registered.remove(event)

	return HttpResponseRedirect(reverse("userDash"))

def register(request):
	registered = False
	if request.user.is_authenticated:
			return HttpResponseRedirect(reverse('index'))
	
	elif request.method == 'POST':
		user_form = UserForm(data=request.POST)
		profile_form = UserProfileForm(data=request.POST)

		if user_form.is_valid() and profile_form.is_valid() :

			user = user_form.save()
			user.set_password(user.password)
			user.save()

			profile = profile_form.save(commit=False)
			profile.user = user
			profile.email = user.email
			profile.save()
			new_user = authenticate(username=user_form.cleaned_data['username'],
									password=user_form.cleaned_data['password'],
						)
			login(request, new_user)
			registered = True

			return HttpResponseRedirect(reverse('index'))

		else:
			print(user_form.errors, profile_form.errors)
	else:
		user_form = UserForm()
		profile_form = UserProfileForm()
	
	return render(request, 'registration/user_register.html', {'registered':registered, 'user_form': user_form, 'profile_form': profile_form})



@login_required
def activate_email(request):
	user = request.user
	current_site = get_current_site(request)
	mail_subject = 'Activate your CIIE account.'
	message = render_to_string('registration/email_activate.html', {
		'user': user,
		'domain': current_site.domain,
		'uid': urlsafe_base64_encode(force_bytes(user.pk)).decode(),
		'token': account_activation_token.make_token(user),
	})
	email_id = UserProfile.objects.get(user=request.user).email
	if not email_id:
		return render(request, 'global_components/message.html', {'title':'Add email', 'message':'Please specify your email address by editing your profile.'})
	to_email = email_id
	email = EmailMessage(mail_subject, message, to=[to_email])
	email.send()
	return HttpResponse('Please check your email inbox to complete the registration process')

@login_required
def activate(request, uidb64, token):
	try:
		uid = force_text(urlsafe_base64_decode(uidb64))
		user = User.objects.get(pk=uid)
		user_profile = UserProfile.objects.get(user=user)
	except:
		user_profile=None
	if user_profile is not None and account_activation_token.check_token(user, token):
		user_profile.email_activated = True
		user_profile.save()
		return HttpResponseRedirect(reverse('index'))
	else:
		return HttpResponse('Activation link is invalid!')

@login_required
def userProfileEdit(request):
	user = UserProfile.objects.get(user=request.user)
	if request.method == "POST":
		form = UserProfileEditForm(request.POST, request.FILES, instance=user)
		if form.is_valid():
			user = form.save(commit=False)
			user.save()
			return redirect('userDash')
	form = UserProfileEditForm(instance=user)
	return render(request, 'log/profile_edit_form.html', {'form':form, 'username': user.user.username})


@login_required
def EventList(request):
	context = {
		"events" : Event.objects.all(),
	}
	return render(request, "event_list_admin.html", context)


@login_required
def EventUsers(request, event_id):
	event = Event.objects.get(pk=event_id)
	context = {
		"users": event.regEvents.all(),
		"event": event,
	}

	return render(request, "show_users.html", context)