from django.urls import path
from django.conf.urls import url, include
from . import views
from django.contrib.auth import views as auth_views
from django.contrib import admin



urlpatterns = [
    path('', views.index, name="index"),
    path('login/', views.login_view, name="login"),
    path('logout/', views.logout_view, name="logout"),
    path('<int:event_id1>/register/', views.registerForEvent, name="register"),
    path('<int:event_id2>/unregister/', views.unregisterForEvent, name="unregister"),
    path('dashboard/', views.userDash, name="userDash"),
    path('<int:event_id>/viewevent', views.viewEvent, name="viewEvent"),
    path('edit/', views.userProfileEdit, name='edit_profile'),
    path('signup/', views.register, name='signup'),
    path('user_in_an_event/<int:event_id>', views.EventUsers, name='eventUsers'),
    path('event_list', views.EventList, name='eventList'),
    url(r'^password_reset/$', auth_views.password_reset, name='password_reset'),
    url(r'^password_reset/done/$', auth_views.password_reset_done, name='password_reset_done'),
    url(r'^reset/(?P<uidb64>[0-9A-Za-z_\-]+)/(?P<token>[0-9A-Za-z]{1,13}-[0-9A-Za-z]{1,20})/$', auth_views.password_reset_confirm, name='password_reset_confirm'),
    url(r'^reset/done/$', auth_views.password_reset_complete, name='password_reset_complete'),
    url(r'^send_activation_email/$', views.activate_email, name='send_activation_email'),
    url(r'^activate/(?P<uidb64>[0-9A-Za-z_\-]+)/(?P<token>[0-9A-Za-z]{1,13}-[0-9A-Za-z]{1,20})/$', views.activate, name='activate'),
    url(r'^change_password/$', views.change_password, name='change_password'),
    #url(r'adminpanel/', include('admin.site.urls'), name='adminPanel'), 
]
