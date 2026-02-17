# backend_apps/scam_database/views.py

from rest_framework import status
from rest_framework.decorators import api_view, permission_classes,parser_classes
from rest_framework.permissions import AllowAny, IsAuthenticated, IsAdminUser
from rest_framework.response import Response
from django.utils import timezone
from django.db.models import Count, Sum, Q
from datetime import timedelta
from rest_framework.parsers import MultiPartParser, FormParser, JSONParser

from .models import (
    PhoneNumberActive,
    PhoneNumberArchived,
    ScamIncident,
    ScamEvidence,
    ReporterCredibility
)
from .serializers import (
    CheckNumberSerializer,
    CheckNumberResponseSerializer,
    ReportScamSerializer,
    MyReportsSerializer,
    ScamIncidentSerializer,
    NumberDetailsSerializer,
    StatsSerializer
)
from .services import NumberLookupService, ReportService


@api_view(['POST'])
@permission_classes([AllowAny])
def check_number(request):
    """
    Check if phone number is in scam database
    
    POST /api/scam-db/check-number/
    Body: {
        "phone_number": "+254712555123"
    }
    """
    serializer = CheckNumberSerializer(data=request.data)
    
    if not serializer.is_valid():
        return Response(
            {
                'success': False,
                'errors': serializer.errors
            },
            status=status.HTTP_400_BAD_REQUEST
        )
    
    phone_number = serializer.validated_data['phone_number']
    
    # Lookup number
    result = NumberLookupService.check_number(phone_number)
    
    return Response(
        {
            'success': True,
            'data': result
        },
        status=status.HTTP_200_OK
    )


@api_view(['POST'])
@permission_classes([IsAuthenticated])
@parser_classes([MultiPartParser, FormParser, JSONParser])
def report_scam(request):
    """
    Submit a scam report with evidence
    
    POST /api/scam-db/report-scam/
    Headers: Authorization: Bearer <token>
    Body: {
        "phone_number": "+254700888999",
        "scam_type": "kra_impersonation",
        "severity": 95,
        "narrative": "Detailed description...",
        "user_confidence": 10,
        "tags": ["urgent", "threatened"],
        "region": "Nairobi",
        "user_consented_storage": true
    }
    
    Optional fields: audio_file, screenshot_1-3, transcript, etc.
    """
    serializer = ReportScamSerializer(data=request.data)
    
    if not serializer.is_valid():
        return Response(
            {
                'success': False,
                'errors': serializer.errors
            },
            status=status.HTTP_400_BAD_REQUEST
        )
    
    # Submit report
    result = ReportService.submit_report(
        phone_number=serializer.validated_data['phone_number'],
        scam_type=serializer.validated_data['scam_type'],
        severity=serializer.validated_data['severity'],
        reported_by=request.user,
        narrative=serializer.validated_data.get('narrative', ''),
        audio_file=serializer.validated_data.get('audio_file'),
        transcript=serializer.validated_data.get('transcript', ''),
        screenshot_1=serializer.validated_data.get('screenshot_1'),
        screenshot_2=serializer.validated_data.get('screenshot_2'),
        screenshot_3=serializer.validated_data.get('screenshot_3'),
        call_duration=serializer.validated_data.get('call_duration'),
        user_confidence=serializer.validated_data.get('user_confidence', 5),
        tags=serializer.validated_data.get('tags', []),
        amount_lost=serializer.validated_data.get('amount_lost'),
        region=serializer.validated_data.get('region', ''),
        user_consented_storage=serializer.validated_data.get('user_consented_storage', False),
        user_consented_training=serializer.validated_data.get('user_consented_training', False)
    )
    
    if not result['success']:
        return Response(
            {
                'success': False,
                'message': result['message']
            },
            status=status.HTTP_400_BAD_REQUEST
        )
    
    # Serialize incident
    incident_data = ScamIncidentSerializer(result['incident']).data
    
    return Response(
        {
            'success': True,
            'message': result['message'],
            'incident': incident_data,
            'risk_score': result['active_record'].risk_score,
            'evidence_quality': result['evidence'].calculate_evidence_quality(),
            'is_new_number': result['is_new_number']
        },
        status=status.HTTP_201_CREATED
    )


@api_view(['GET'])
@permission_classes([IsAuthenticated])
def my_reports(request):
    """
    Get current user's report history
    
    GET /api/scam-db/my-reports/
    Headers: Authorization: Bearer <token>
    """
    user = request.user
    
    # Get user's incidents
    incidents = ScamIncident.objects.filter(
        reported_by=user
    ).order_by('-reported_at')
    
    # Get credibility
    credibility, _ = ReporterCredibility.objects.get_or_create(user=user)
    
    # Serialize
    response_data = {
        'incidents': ScamIncidentSerializer(incidents, many=True).data,
        'total_reports': credibility.total_reports,
        'verified_reports': credibility.verified_reports,
        'pending_reports': credibility.pending_reports,
        'credibility_tier': credibility.credibility_tier,
        'credibility_score': credibility.credibility_score
    }
    
    return Response(
        {
            'success': True,
            'data': response_data
        },
        status=status.HTTP_200_OK
    )


@api_view(['GET'])
@permission_classes([AllowAny])
def number_details(request, phone_number):
    """
    Get detailed information about a number
    
    GET /api/scam-db/number-details/{phone_number}/
    Example: /api/scam-db/number-details/+254700888999/
    """
    # Basic lookup
    lookup = NumberLookupService.check_number(phone_number)
    
    # Get statistics
    stats = NumberLookupService.get_statistics(phone_number)
    
    # Combine data
    response_data = {
        'status': lookup['status'],
        'risk_score': lookup['risk_score'],
        'risk_level': lookup['risk_level'],
        'scam_type': lookup['scam_type'],
        'report_count': lookup['report_count'],
        'verified_reports': lookup['verified_reports'],
        'last_reported': lookup['last_reported'],
        'total_incidents': stats['total_incidents'],
        'total_amount_lost': stats['total_amount_lost'],
        'scam_types_distribution': stats['scam_types_distribution'],
        'recent_incidents': ScamIncidentSerializer(
            stats['recent_incidents'],
            many=True
        ).data
    }
    
    return Response(
        {
            'success': True,
            'data': response_data
        },
        status=status.HTTP_200_OK
    )


@api_view(['GET'])
@permission_classes([IsAdminUser])
def admin_stats(request):
    """
    Get overall system statistics (admin only)
    
    GET /api/scam-db/admin/stats/
    Headers: Authorization: Bearer <admin-token>
    """
    # Count totals
    total_active = PhoneNumberActive.objects.count()
    total_archived = PhoneNumberArchived.objects.count()
    total_incidents = ScamIncident.objects.count()
    
    # Time-based reports
    now = timezone.now()
    today_start = now.replace(hour=0, minute=0, second=0, microsecond=0)
    week_start = now - timedelta(days=7)
    month_start = now - timedelta(days=30)
    
    reports_today = ScamIncident.objects.filter(reported_at__gte=today_start).count()
    reports_week = ScamIncident.objects.filter(reported_at__gte=week_start).count()
    reports_month = ScamIncident.objects.filter(reported_at__gte=month_start).count()
    
    # Risk distribution
    high_risk = PhoneNumberActive.objects.filter(risk_score__gte=70).count()
    medium_risk = PhoneNumberActive.objects.filter(
        risk_score__gte=30,
        risk_score__lt=70
    ).count()
    
    # Scam types breakdown
    scam_types = ScamIncident.objects.values('scam_type').annotate(
        count=Count('id')
    ).order_by('-count')
    
    scam_types_breakdown = {
        item['scam_type']: item['count']
        for item in scam_types
    }
    
    top_scam_types = list(scam_types[:5])
    
    response_data = {
        'total_active_numbers': total_active,
        'total_archived_numbers': total_archived,
        'total_incidents': total_incidents,
        'total_reports_today': reports_today,
        'total_reports_week': reports_week,
        'total_reports_month': reports_month,
        'high_risk_count': high_risk,
        'medium_risk_count': medium_risk,
        'scam_types_breakdown': scam_types_breakdown,
        'top_scam_types': top_scam_types
    }
    
    return Response(
        {
            'success': True,
            'data': response_data
        },
        status=status.HTTP_200_OK
    )


@api_view(['GET'])
@permission_classes([AllowAny])
def health_check(request):
    """
    Health check endpoint
    
    GET /api/scam-db/health/
    """
    return Response(
        {
            'status': 'healthy',
            'service': 'CallShield Scam Database API',
            'timestamp': timezone.now().isoformat()
        },
        status=status.HTTP_200_OK
    )