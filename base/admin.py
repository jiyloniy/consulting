from django.contrib import admin
from .models import University,Lids,Harajatlar,Shartnoma,Tarif
from django.contrib.auth import get_user_model
User = get_user_model()

class UserAdmin(admin.ModelAdmin):
    list_display = ['id','name','phone','email','is_active','is_staff','is_superuser','created_at','updated_at']
    list_display_links = ['name']
    list_filter = ['id','name','phone','email','is_active','is_staff','is_superuser','created_at','updated_at']
    search_fields = ['name','phone','email']
    list_per_page = 20
    class Meta:
        model = User

class UniversityAdmin(admin.ModelAdmin):
    list_display = ['id','name','type','city','rank','requirements','dastur','scholarships','departments','img','created_at','updated_at','url_link']
    list_display_links = ['name']
    list_filter = ['id','name','type','city','rank','requirements','dastur','scholarships','departments','img','created_at','updated_at','url_link']
    search_fields = ['name','type','city','rank','requirements','dastur','scholarships','departments','img','url_link']
    list_per_page = 20
    class Meta:
        model = University


class LidsAdmin(admin.ModelAdmin):
    list_display = ['id','type','name','phone','created_at','updated_at']
    list_display_links = ['name']
    list_filter = ['id','type','name','phone','created_at','updated_at']
    search_fields = ['name','phone']
    list_per_page = 20
    class Meta:
        model = Lids


class TarifAdmin(admin.ModelAdmin):
    list_display = ['id','name','price','description','created_at','updated_at']
    list_display_links = ['name']
    list_filter = ['id','name','price','description','created_at','updated_at']
    search_fields = ['name','price','description']
    list_per_page = 20
    class Meta:
        model = Tarif



class HarajatlarAdmin(admin.ModelAdmin):
    list_display = ['id','name','price','description','created_at','updated_at']
    list_display_links = ['name']
    list_filter = ['id','name','price','description','created_at','updated_at']
    search_fields = ['name','price','description']
    list_per_page = 20
    class Meta:
        model = Harajatlar


class ShartnomaAdmin(admin.ModelAdmin):
    list_display = ['id','name','created_at','updated_at']
    list_display_links = ['name']
    list_filter = ['id','name','created_at','updated_at']
    search_fields = ['name','description'] 
    list_per_page = 20
    class Meta:
        model = Shartnoma



# admin.site.register(User, UserAdmin)
admin.site.register(University, UniversityAdmin)
admin.site.register(Lids, LidsAdmin)
admin.site.register(Tarif, TarifAdmin)
admin.site.register(Harajatlar, HarajatlarAdmin)
admin.site.register(Shartnoma, ShartnomaAdmin)