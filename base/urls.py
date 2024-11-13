# urls py
from django.urls import path
from .views import UserViewSet, UniversityViewSet, LidsViewSet, HarajatlarViewSet, ShartnomaViewSet,LoginView,LogoutView,TarifViewSet
from rest_framework.routers import DefaultRouter
from .statistics import LeadStatistic
router = DefaultRouter()
router.register(r'users', UserViewSet)
router.register(r'universities', UniversityViewSet)
router.register(r'lids', LidsViewSet)
router.register(r'harajatlar', HarajatlarViewSet)

router.register(r'shartnoma', ShartnomaViewSet)
router.register(r'tarif', TarifViewSet)

urlpatterns = router.urls

urlpatterns += [
    path('login/', LoginView.as_view(), name='login'),
    path('logout/', LogoutView.as_view(), name='logout'),
    path('lidsstatic/', LeadStatistic.as_view(), name='lids'),
]
