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
from .permissin import ReadORAuditPermission,PostAndAuhtorPermission

User = get_user_model()
class LogoutView(APIView):
    authentication_classes = [JWTAuthentication]
    permission_classes = [IsAuthenticated]

    def post(self, request):
        try:
            refresh_token = request.data["refresh_token"]
            token = RefreshToken(refresh_token)
            token.blacklist()
            return Response(status=status.HTTP_205_RESET_CONTENT)
        except Exception as e:
            return Response(status=status.HTTP_400_BAD_REQUEST)
        
class LoginView(APIView):
    def post(self, request):
        print(request.query_params)
        username = request.data.get("username") 
        if username is None:
            username = request.query_params.get("username")
        
        password = request.data.get("password")
        if password is None:
            password = request.query_params.get("password")
        users = User.objects.all()
        print(users)
        user = User.objects.filter(username=username).first()
        print(user)
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
    permission_classes = [ReadORAuditPermission]
    
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
