from django.contrib import admin
from .models import UserProfile, Event
#from simple_mail.models import 

# Register your models here.
class EventUser(admin.ModelAdmin):
	model = UserProfile
	filter_horizontal = ('events_registered',)

admin.site.register(UserProfile, EventUser,list_display=['user','name' , 'email', 'course', 'institution', 'graduation_year','email_activated',])
admin.site.register(Event, list_display=['title','author','date','event_date','time','venue','content','slug',])
