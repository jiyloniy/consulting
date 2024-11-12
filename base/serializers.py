from rest_framework import serializers

from .models import University,Lids,Harajatlar,Shartnoma,Tarif
# abstract user model
from django.contrib.auth import get_user_model
User = get_user_model()

class UserSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = '__all__'


class UniversitySerializer(serializers.ModelSerializer):
    class Meta:
        model = University
        fields = '__all__'


class LidsSerializer(serializers.ModelSerializer):
    class Meta:
        model = Lids
        fields = '__all__'



class HarajatlarSerializer(serializers.ModelSerializer):
    class Meta:
        model = Harajatlar
        fields = '__all__'


class ShartnomaSerializer(serializers.ModelSerializer):
    class Meta:
        model = Shartnoma
        fields = '__all__'


class TarifSerializer(serializers.ModelSerializer):
    class Meta:
        model = Tarif
        fields = '__all__'


