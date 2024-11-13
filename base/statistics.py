from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework.response import Response
from rest_framework import status
from django.db.models import Count
from django.db.models.functions import TruncDate,TruncWeek, TruncYear,TruncMonth
from django.utils import timezone
from datetime import timedelta
from rest_framework_simplejwt.authentication import JWTAuthentication
from rest_framework.permissions import IsAuthenticated
from .models import Lids
# statistika lidslar uchun
from django.db.models.functions import TruncYear, TruncMonth, TruncWeek
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework.permissions import IsAuthenticated
from rest_framework import status
from django.utils import timezone
from django.db.models import Count
from .models import Lids

class LeadStatistic(APIView):
    authentication_classes = [JWTAuthentication]
    permission_classes = [IsAuthenticated]

    def get(self, request):
        try:
            # Yillik statistika
            yearly_stats = (
                Lids.objects
                .annotate(year=TruncYear('created_at'))
                .values('year')
                .annotate(total=Count('id'))
                .order_by('year')
            )
            leads = Lids.objects.all().count()
            # Joriy yil
            current_year = timezone.now().year
            # Oylik statistika (faqat joriy yil uchun)
            monthly_stats = (
                Lids.objects
                .filter(created_at__year=current_year)
                .annotate(month=TruncMonth('created_at'))
                .values('month')
                .annotate(total=Count('id'))
                .order_by('month')
            )
            # Haftalik statistika (so'nggi 12 hafta)
            weekly_stats = (
                Lids.objects
                .filter(created_at__gte=timezone.now() - timezone.timedelta(weeks=12))
                .annotate(week=TruncWeek('created_at'))
                .values('week')
                .annotate(total=Count('id'))
                .order_by('week')
            )

            # Javob berish uchun ma'lumotlarni tayyorlash
            response_data = {
                'yearly': [
                    {
                        'date': item['year'].strftime('%Y'),
                        'total': item['total']
                    } for item in yearly_stats
                ],
                'monthly': [
                    {
                        'date': item['month'].strftime('%Y-%m'),
                        'total': item['total']
                    } for item in monthly_stats
                ],
                'weekly': [
                    {
                        'date': item['week'].strftime('%Y-%m-%d'),
                        'total': item['total']
                    } for item in weekly_stats
                ],
                'total_lids':[
                    {
                        'total':leads
                    }
                ]
            }
            print(response_data)
            return Response(response_data)
        except Exception as e:
            return Response(
                status=status.HTTP_500_INTERNAL_SERVER_ERROR,
                data={'error': str(e)}
            )
