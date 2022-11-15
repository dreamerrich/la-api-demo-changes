from django.urls import path
from .views import RegisterAPIView, LoginView
urlpatterns = [
    path('register',RegisterAPIView.as_view()),
    path('login', LoginView.as_view(), name='login'),
]