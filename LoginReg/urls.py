from django.urls import path
from . import views

urlpatterns = [
    path('',views.index),
    path('register',views.register),
    path('login',views.login),
    path('logout',views.logout),
    path('show_all',views.show_all),
    path('delete/<int:user_id>',views.delete),
    path('update',views.update),
    path('change_password',views.change_password)
]
