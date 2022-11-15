from django.shortcuts import render
from rest_framework.views import APIView
from django.contrib.auth import get_user_model
from rest_framework.response import Response
from  .serializers import RegisterSerializer, LoginSerializer, projectSerializer
from rest_framework.permissions import AllowAny, IsAuthenticated
from rest_framework.views import APIView
from rest_framework import generics
from django.contrib.auth.models import update_last_login
from rest_framework_jwt.settings import api_settings
JWT_PAYLOAD_HANDLER = api_settings.JWT_PAYLOAD_HANDLER
JWT_ENCODE_HANDLER = api_settings.JWT_ENCODE_HANDLER
from rest_framework.authtoken.models import Token
from rest_framework_simplejwt.tokens import RefreshToken
from .models import CustomUser
from django.conf import settings
from django.contrib.auth import authenticate
from rest_framework import status
from django.contrib.auth.models import User
from rest_framework import viewsets


# Create your views here.

#Class based view to register user
class RegisterAPIView(generics.CreateAPIView):
  permission_classes = (AllowAny,)
  serializer_class = RegisterSerializer

class LoginView(generics.CreateAPIView):
    permission_classes = (AllowAny,)
    serializer_class = LoginSerializer

    def get(self, request):
        serializer = self.serializer_class(data=request.data)
        serializer.is_valid(raise_exception=True)
        if serializer.is_valid():
            username = request.data.get("username", None)
            print("🚀 ~ file: views.py ~ line 37 ~ username", username)
            password = request.data.get("password")
            print("🚀 ~ file: views.py ~ line 39 ~ password", password)
            try:
                user = User.objects.get(username=username)
            except:
                user = None
                return Response({"error": "Your username is not correct. Please try again or register your details"})
            # if user.user_type == 'user':
                # print('',user)
            token = RefreshToken.for_user(user)

            user = authenticate(username=username, password=password)
            print("🚀 ~ file: views.py ~ line 42 ~ user", user)
            if user is not None:
                payload = JWT_PAYLOAD_HANDLER(user)
                jwt_token = JWT_ENCODE_HANDLER(payload)
                jwt_access_token_lifetime =  settings.SIMPLE_JWT['ACCESS_TOKEN_LIFETIME']
                jwt_refresh_token_lifetime =  settings.SIMPLE_JWT['REFRESH_TOKEN_LIFETIME']
                update_last_login(None, user)
                response = {
                                    'success': 'True',
                                    'status code': status.HTTP_200_OK,
                                    'message': 'User logged in successfully',
                                    'access': str(token.access_token),
                                    'referesh_token':str(token),
                                    "access_token_life_time_in_seconds" : jwt_access_token_lifetime.total_seconds(),
                                    "refresh_token_life_time_in_seconds" : jwt_refresh_token_lifetime.total_seconds(),
                                }
                status_code = status.HTTP_200_OK
                return Response(response, status=status_code)
            else:
                return Response({"error": 'Your password is not correct please try again or reset your password'}, status=401)

class projectData(viewsets.ViewSet):
    permission_classes = [IsAuthenticated, ]
    serializer_class = projectSerializer

    def create():
        pass

    def get():
        pass

    def update():
        pass

    def partial_update():
        pass

    def delete():
        pass


