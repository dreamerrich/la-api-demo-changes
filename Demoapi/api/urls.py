from django.urls import path, include
from .views import RegisterAPIView, LoginView, projectViewSet, filterSort
from rest_framework.routers import DefaultRouter

router = DefaultRouter()
router.register(r'project', projectViewSet, basename='project')

urlpatterns = [
    path('register',RegisterAPIView.as_view()),
    path('login', LoginView.as_view(), name='login'),
    path('viewset',include(router.urls)),
    path('filter', filterSort.as_view()),
]