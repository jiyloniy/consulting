from .models import University,Lids,Harajatlar,Shartnoma,Tarif
from .serializers import UserSerializer,UniversitySerializer,LidsSerializer,HarajatlarSerializer,ShartnomaSerializer,TarifSerializer
from rest_framework import viewsets
from rest_framework import permissions
from rest_framework.pagination import PageNumberPagination
from rest_framework_simplejwt.authentication import JWTAuthentication
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from rest_framework.views import APIView
from rest_framework import status
from rest_framework_simplejwt.tokens import RefreshToken
from django.contrib.auth import get_user_model
from rest_framework_simplejwt.exceptions import TokenError
from .permissin import ReadORAuditPermission,PostAndAuhtorPermission

User = get_user_model()
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from rest_framework_simplejwt.tokens import RefreshToken, TokenError
from django.core.exceptions import ObjectDoesNotExist
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from rest_framework_simplejwt.exceptions import TokenError
from rest_framework_simplejwt.tokens import RefreshToken
from django.core.exceptions import ObjectDoesNotExist
from rest_framework_simplejwt.token_blacklist.models import OutstandingToken, BlacklistedToken

class LogoutView(APIView):
    permission_classes = []
    
    def post(self, request):
        try:
            refresh_token = request.data.get("refresh_token")
            if not refresh_token:
                return Response(
                    {"error": "Refresh token is required"}, 
                    status=status.HTTP_400_BAD_REQUEST
                )

            # Convert the token string to a RefreshToken instance
            token = RefreshToken(refresh_token)
            
            # Use blacklist if available
            if hasattr(token, 'blacklist'):
                token.blacklist()
                return Response(
                    {"detail": "Successfully logged out"}, 
                    status=status.HTTP_200_OK
                )

            # Alternative approach if blacklist() is not available
            outstanding_token = OutstandingToken.objects.get(
                jti=token['jti'],
                user_id=token['user_id']
            )
            BlacklistedToken.objects.get_or_create(token=outstanding_token)
            
            return Response(
                {"detail": "Successfully logged out"}, 
                status=status.HTTP_200_OK
            )

        except ObjectDoesNotExist:
            return Response(
                {"error": "Token is invalid or expired"},
                status=status.HTTP_400_BAD_REQUEST
            )
        except TokenError:
            return Response(
                {"error": "Invalid or expired token"},
                status=status.HTTP_400_BAD_REQUEST
            )
        except Exception as e:
            return Response(
                {"error": str(e)},
                status=status.HTTP_400_BAD_REQUEST
            )

class LoginView(APIView):
    def post(self, request):
        
        username = request.data.get("username") 
        if username is None:
            username = request.query_params.get("username")
        
        password = request.data.get("password")
        if password is None:
            password = request.query_params.get("password")
        users = User.objects.all()
        
        user = User.objects.filter(username=username).first()
        
        if user is None:
            return Response({"error": "Invalid email"}, status=status.HTTP_400_BAD_REQUEST)
        if not user.check_password(password):
            return Response({"error": "Invalid password"}, status=status.HTTP_400_BAD_REQUEST)
        refresh = RefreshToken.for_user(user)
        return Response({
            "refresh": str(refresh),
            "access": str(refresh.access_token)
        })

class UserViewSet(viewsets.ModelViewSet):
    queryset = User.objects.all()
    serializer_class = UserSerializer
    permission_classes = [permissions.IsAuthenticated]
 
    pagination_class = PageNumberPagination


class UniversityViewSet(viewsets.ModelViewSet):
    queryset = University.objects.all()
    serializer_class = UniversitySerializer
    permission_classes = [ReadORAuditPermission]
    
    pagination_class = PageNumberPagination


class LidsViewSet(viewsets.ModelViewSet):
    queryset = Lids.objects.all()
    serializer_class = LidsSerializer
    permission_classes = [PostAndAuhtorPermission]
   
    pagination_class = PageNumberPagination


class HarajatlarViewSet(viewsets.ModelViewSet):
    queryset = Harajatlar.objects.all()
    serializer_class = HarajatlarSerializer
    permission_classes = [IsAuthenticated]
    
    pagination_class = PageNumberPagination


class ShartnomaViewSet(viewsets.ModelViewSet):
    queryset = Shartnoma.objects.all()
    serializer_class = ShartnomaSerializer
    permission_classes = [ReadORAuditPermission]
   
    pagination_class = PageNumberPagination


class TarifViewSet(viewsets.ModelViewSet):
    queryset = Tarif.objects.all()
    serializer_class = TarifSerializer
    permission_classes = [ReadORAuditPermission]
   
    pagination_class = PageNumberPagination






