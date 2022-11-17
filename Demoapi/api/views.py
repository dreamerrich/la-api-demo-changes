from django.shortcuts import render
from django.contrib.auth import get_user_model
from rest_framework.response import Response
from  .serializers import RegisterSerializer, LoginSerializer, projectSerializer
from rest_framework.permissions import AllowAny, IsAuthenticated
from rest_framework.generics import CreateAPIView, GenericAPIView
from rest_framework.views import APIView
from rest_framework import generics
from django.contrib.auth.models import update_last_login
from rest_framework_jwt.settings import api_settings
JWT_PAYLOAD_HANDLER = api_settings.JWT_PAYLOAD_HANDLER
JWT_ENCODE_HANDLER = api_settings.JWT_ENCODE_HANDLER
from rest_framework.authtoken.models import Token
from rest_framework_simplejwt.tokens import RefreshToken
from .models import CustomUser,Project
from django.conf import settings
from django.contrib.auth import authenticate
from rest_framework import status
from django.contrib.auth.models import User
from rest_framework import filters
from django.http import Http404
# from rest_framework_jwt.authentication import JSONWebTokenAuthentication

# Create your views here.

#--------------- Class based view to register user -----------------
class RegisterApiView(APIView):
    queryset = User.objects.all()
    permission_classes = (AllowAny,)

    def get(self, request):
        queryset = User.objects.all()
        serializer_class = RegisterSerializer(queryset, many=True)
        return Response(serializer_class.data)

    def post(self, request):
        serializer_class = RegisterSerializer(data=request.data)
        if serializer_class.is_valid():
            serializer_class.save()
            return Response(serializer_class.data, status=status.HTTP_201_CREATED)
        return Response(serializer_class.errors, status=status.HTTP_400_BAD_REQUEST)


# ------------- login view -----------------
class LoginView(APIView):
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
                # jwt_token = JWT_ENCODE_HANDLER(payload)
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

#------------- creating data --------------
class projectListView(APIView):
    permission_classes = [IsAuthenticated, ]
    # authentication_class = JSONWebTokenAuthentication
    filter_backends = (filters.SearchFilter,)
    search_fields = ["project_name", "color"]

    def filter_queryset(self, queryset):

        for backend in list(self.filter_backends):
            queryset = backend().filter_queryset(self.request, queryset, self)
            print("🚀 ~ file: views.py ~ line 21 ~ queryset", queryset)
            return queryset

    def get_queryset(self):
        user = self.request.user
        return Project.objects.filter(created_by=user).order_by("created_at")
        # return Project.objects.filter(created_by=user).order_by("-created_at")

    def get(self, request, format=None):
        the_filtered_qs = self.filter_queryset(self.get_queryset())
        serializer = projectSerializer(the_filtered_qs, many=True)
        print("🚀 ~ file: views.py ~ line 30 ~ serializer", serializer)
        return Response(serializer.data)

    def post(self, request, format=None):
        serializer = projectSerializer(data=request.data)
        if serializer.is_valid():
            data = self.request.user
            print("🚀 ~ file: views.py ~ line 117 ~ data", data)
            serializer.save()
            return Response(serializer.data, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

#------------- CRUD operations ------------
class projectDetails(APIView):
    
    def get_object(self, pk):
        print("🚀 ~ file: views.py ~ line 44 ~ id", pk)
        try:
            user = self.request.user
            return Project.objects.filter(created_by=user).get(pk=pk)
        except Project.DoesNotExist as e:
            raise Http404 from e

    def get(self, request, pk, format=None):
        project_data = self.get_object(pk)
        print("🚀 ~ file: views.py ~ line 55 ~ project_data", project_data)
        serializer = projectSerializer(project_data)
        return Response(serializer.data)

    def patch(self, request, pk, format=None):
        project_data = self.get_object(pk)
        serializer = projectSerializer(project_data, data=request.data)
        print("🚀 ~ file: views.py ~ line 63 ~ serializer", serializer)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    def put(self, request, pk, format=None):
        project_data = self.get_object(pk)
        serializer = projectSerializer(project_data, data=request.data, partial=True)
        print("🚀 ~ file: views.py ~ line 62 ~ serializer", serializer)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    def delete(self, request, pk, format=None):
        project_data = self.get_object(pk)
        project_data.delete()
        return Response(status=status.HTTP_204_NO_CONTENT)