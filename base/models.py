from django.db import models
from django.contrib.auth.models import AbstractUser


class University(models.Model):
    name = models.CharField(max_length=255)

    types = (
        (1,'junior'),
        (2,'middle'),
        (3,'senior'),
    )
    type = models.IntegerField(choices=types,default=1)
    city = models.CharField(max_length=255)
    rank = models.JSONField()
    requirements = models.JSONField()
    
    dastur = models.JSONField()
   
    scholarships = models.JSONField()
   
    departments = models.JSONField()
    img = models.ImageField(upload_to='universities/',blank=True,null=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    url_link = models.URLField(blank=True,null=True)
    is_active = models.BooleanField(default=True)
    comments = models.JSONField()
    def __str__(self):
        return self.name

class Lids(models.Model):
    types = (
        (1,'yangi'),
        (2,'kutilayotgan'),
        (3,'shartnoma qilingan'),
        (4,'toxtatilgan'),

    )
    type = models.IntegerField(choices=types,default=1)
    name = models.CharField(max_length=255)
    phone = models.CharField(max_length=255)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    
    def __str__(self):
        return self.name
    


class Tarif(models.Model):
    name = models.CharField(max_length=255)
    price = models.FloatField()
    description = models.JSONField()
    futures = models.JSONField()
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    
    def __str__(self):
        return self.name
       
class Shartnoma(models.Model):
    name = models.CharField(max_length=255)
    second_name = models.CharField(max_length=255)
    phone = models.CharField(max_length=255)
    tarif = models.ForeignKey(Tarif,on_delete=models.CASCADE)
    university = models.ForeignKey(University,on_delete=models.CASCADE)
    price = models.FloatField()
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    def __str__(self):
        return self.name
    

class Harajatlar(models.Model):
    name = models.CharField(max_length=255)
    price = models.FloatField()
    description = models.JSONField()
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    
    def __str__(self):
        return self.name
