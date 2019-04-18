#Models files
from django.db import models
import datetime
from django.contrib.auth.models import User
from django.utils.translation import gettext as _
from django.template.defaultfilters import slugify
from django.core.validators import RegexValidator

# Create your models here.

class Event(models.Model):
	title  = models.CharField(max_length=255)
	author = models.CharField(max_length=255)
	date = models.DateTimeField(auto_now_add=True)
	event_date = models.DateTimeField()
	time = models.TimeField()
	venue = models.CharField(max_length=1024)
	content = models.TextField()
	slug = models.SlugField(db_index=True, unique=True, max_length=2024)
	
	def __str__(self):
		return self.title

class UserProfile(models.Model):

	user = models.OneToOneField(User, on_delete=models.CASCADE)
	name = models.CharField(max_length=255, blank=True)
	email = models.EmailField(max_length=255, unique=True)
	institution = models.CharField(max_length=255, blank=True)
	course = models.CharField(max_length=255, blank=True)
	phone_regex = RegexValidator(regex=r'^\d{9,10}$')
	phone_number = models.CharField(validators=[phone_regex], max_length=10, blank=False, null=True, unique=True)
	events_registered = models.ManyToManyField(Event, blank=True, related_name="regEvents")
	YEAR_CHOICES = []

	for i in range((datetime.datetime.now().year),(datetime.datetime.now().year+10)):
		YEAR_CHOICES.append((i,i))

	graduation_year = models.IntegerField(_('year'), choices=YEAR_CHOICES,default=datetime.datetime.now().year)

	bio = models.TextField(blank=True)
	email_activated = models.BooleanField(default=False)
	last_login_time = models.DateTimeField(blank=True, null=True)
	ip_address  = models.CharField(blank=True,max_length=255)
	user_agent = models.CharField(blank=True, max_length=1024)

	def __str__(self):
		return self.user.username

