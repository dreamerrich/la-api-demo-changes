from django.urls import path, include
from .views import RegisterApiView, LoginView, projectViewSet, filterSort
from rest_framework.routers import DefaultRouter

router = DefaultRouter()
router.register(r'details', projectViewSet, basename='project')

urlpatterns = [
    path('register',RegisterApiView.as_view()),
    path('login', LoginView.as_view(), name='login'),
    path('api/', include(router.urls)),
    # path('project', projectApiView.as_view()),
    path('filter', filterSort.as_view()),
]