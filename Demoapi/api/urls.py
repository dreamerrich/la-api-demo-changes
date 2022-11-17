from django.urls import path, include
from .views import RegisterApiView, LoginView, LoginView,projectListView, projectDetails


urlpatterns = [
    path('register',RegisterApiView.as_view()),
    path('login', LoginView.as_view(), name='login'),
    path('project', projectListView.as_view()),
    path('details/<int:pk>', projectDetails.as_view()),
]