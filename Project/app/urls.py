from django.urls import path
from . import views

urlpatterns = [
    path('', views.login_view, name='login'),
    path('signup/', views.signup, name='signup'),
    path('dashboard/', views.dashboard, name='dashboard'),
    path('logout/', views.logout_view, name='logout'),
    path('create-group/', views.create_group_view, name='create_group'),
    path('join-group/', views.join_group_view, name='join_group'),
    path('chat/', views.chat_view, name='chat'),
]