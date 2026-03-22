from rest_framework import status
from rest_framework.decorators import api_view, permission_classes
from rest_framework.permissions import IsAuthenticated, IsAdminUser, AllowAny
from rest_framework.response import Response

from .services import (
    UserAnalyticsService,
    AdminAnalyticsService,
    PublicAnalyticsService
)
from .serializers import (
    UserStatsSerializer,
    SystemOverviewSerializer,
    TimeBasedActivitySerializer,
    ScamTrendsSerializer,
    UserEngagementSerializer,
    CommunityImpactSerializer,
    ScamIntelligenceSerializer
)


# USER ANALYTICS (Personal Dashboard)


@api_view(['GET'])
@permission_classes([IsAuthenticated])
def user_stats(request):
    """
    Get comprehensive analytics for the authenticated user.
    
    GET /api/analytics/user/stats/
    Authorization: Bearer <token>
    
    Returns:
    - Protection stats (calls, scams, success rate)
    - Call summary (scam vs safe breakdown)
    - Community impact (reports, contributions, users helped)
    - Recent activity (7-day timeline)
    - Scam types encountered
    """
    data = UserAnalyticsService.get_user_stats(request.user)
    serializer = UserStatsSerializer(data)
    
    return Response({
        'success': True,
        'data': serializer.data
    }, status=status.HTTP_200_OK)


# ADMIN ANALYTICS (Internal Dashboard)


@api_view(['GET'])
@permission_classes([IsAdminUser])
def system_overview(request):
    """
    Get system-wide overview statistics.
    
    GET /api/analytics/admin/overview/
    Authorization: Bearer <admin-token>
    
    Returns:
    - User counts (total, active today/week/month)
    - Detection stats (sessions, scams, detection rate)
    - Database stats (active numbers, reports, training data)
    - ML model status
    """
    data = AdminAnalyticsService.get_system_overview()
    serializer = SystemOverviewSerializer(data)
    
    return Response({
        'success': True,
        'data': serializer.data
    }, status=status.HTTP_200_OK)


@api_view(['GET'])
@permission_classes([IsAdminUser])
def time_based_activity(request):
    """
    Get activity stats broken down by time period.
    
    GET /api/analytics/admin/activity/
    Authorization: Bearer <admin-token>
    
    Returns:
    - Today's activity (sessions, scams, reports)
    - This week's activity
    - This month's activity
    """
    data = AdminAnalyticsService.get_time_based_activity()
    serializer = TimeBasedActivitySerializer(data)
    
    return Response({
        'success': True,
        'data': serializer.data
    }, status=status.HTTP_200_OK)


@api_view(['GET'])
@permission_classes([IsAdminUser])
def scam_trends(request):
    """
    Get scam type distribution and trends.
    
    GET /api/analytics/admin/trends/
    Authorization: Bearer <admin-token>
    
    Returns:
    - Scam type distribution (last 30 days)
    - Trending up (increasing scam types)
    - Trending down (decreasing scam types)
    """
    data = AdminAnalyticsService.get_scam_trends()
    serializer = ScamTrendsSerializer(data)
    
    return Response({
        'success': True,
        'data': serializer.data
    }, status=status.HTTP_200_OK)


@api_view(['GET'])
@permission_classes([IsAdminUser])
def user_engagement(request):
    """
    Get user engagement metrics.
    
    GET /api/analytics/admin/engagement/
    Authorization: Bearer <admin-token>
    
    Returns:
    - DAU/WAU/MAU (daily/weekly/monthly active users)
    - Average sessions per user
    - Average reports per user
    - Training contributor percentage
    - Top contributors
    """
    data = AdminAnalyticsService.get_user_engagement()
    serializer = UserEngagementSerializer(data)
    
    return Response({
        'success': True,
        'data': serializer.data
    }, status=status.HTTP_200_OK)


# PUBLIC ANALYTICS (Marketing Website)


@api_view(['GET'])
@permission_classes([AllowAny])
def community_impact(request):
    """
    Get public community impact statistics.
    No authentication required - for marketing website.
    
    GET /api/analytics/public/impact/
    
    Returns:
    - Total scams blocked
    - Total users protected
    - Success rate
    - Active users now
    - Today's stats
    - Community strength
    """
    data = PublicAnalyticsService.get_community_impact()
    serializer = CommunityImpactSerializer(data)
    
    return Response({
        'success': True,
        'data': serializer.data
    }, status=status.HTTP_200_OK)


@api_view(['GET'])
@permission_classes([AllowAny])
def scam_intelligence(request):
    """
    Get public scam intelligence (no PII).
    No authentication required - for marketing website.
    
    GET /api/analytics/public/scam-intelligence/
    
    Returns:
    - Scam type distribution (percentages only)
    - Most common scam type
    """
    data = PublicAnalyticsService.get_scam_intelligence()
    serializer = ScamIntelligenceSerializer(data)
    
    return Response({
        'success': True,
        'data': serializer.data
    }, status=status.HTTP_200_OK)


@api_view(['GET'])
@permission_classes([AllowAny])
def public_stats_mobile(request):
    """
    Get public stats optimized for mobile app.
    Only shows scam types that have been detected.
    
    GET /api/analytics/public/mobile/
    """
    print("🔵 public_stats_mobile endpoint called")
    
    try:
        from backend_apps.scam_database.models import ScamIncident
        from backend_apps.authentication.models import User
        from django.db.models import Count
        
        # 1. Total Users Protected
        total_users_protected = User.objects.filter(is_active=True).count()
        print(f"🔵 Total users: {total_users_protected}")
        
        # 2. Verified Reports Count (ONLY verified incidents)
        verified_reports = ScamIncident.objects.filter(verified=True).count()
        print(f"🔵 Verified reports: {verified_reports}")
        
        # 3. Get ALL scam detections (from reports AND AI detection)
        # Combine ScamIncident scam_types with CallSession scam_types
        
        # Only verified/approved reports feed the distribution — no AI sessions, no pending
        incident_scams = ScamIncident.objects.filter(
            verified=True
        ).values('scam_type').annotate(
            count=Count('id')
        ).filter(count__gt=0)

        scam_counts = {}
        for item in incident_scams:
            scam_type = item['scam_type']
            if scam_type:
                scam_counts[scam_type] = scam_counts.get(scam_type, 0) + item['count']
        
        print(f"🔵 Combined scam types found: {len(scam_counts)}")
        
        # Sort by count (descending)
        sorted_scams = sorted(scam_counts.items(), key=lambda x: x[1], reverse=True)
        
        # Get top scam type
        if sorted_scams:
            from backend_apps.scam_database.models import ScamType
            top_scam_code = sorted_scams[0][0]
            top_scam_count = sorted_scams[0][1]
            top_scam_type = dict(ScamType.choices).get(top_scam_code, top_scam_code)
        else:
            top_scam_type = "No scams detected yet"
            top_scam_count = 0
        
        print(f"🔵 Top scam: {top_scam_type} ({top_scam_count})")
        
        # 4. Create distribution (ONLY scam types that exist)
        total_scam_count = sum(scam_counts.values())
        
        scam_distribution = []
        for scam_code, count in sorted_scams[:5]:  # Top 5 only
            from backend_apps.scam_database.models import ScamType
            scam_label = dict(ScamType.choices).get(scam_code, scam_code)
            percentage = round((count / total_scam_count * 100), 1) if total_scam_count > 0 else 0
            
            scam_distribution.append({
                'scam_type': scam_label,
                'count': count,
                'percentage': percentage
            })
        
        print(f"🔵 Distribution items: {len(scam_distribution)}")
        
        # 5. Return data
        return Response({
            'success': True,
            'total_users_protected': total_users_protected,
            'verified_reports': verified_reports,
            'top_scam_type': top_scam_type,
            'top_scam_count': top_scam_count,
            'scam_distribution': scam_distribution,
            'total_scam_types': len(scam_counts)  # How many different types detected
        }, status=status.HTTP_200_OK)
        
    except Exception as e:
        print(f"❌ ERROR: {e}")
        import traceback
        traceback.print_exc()
        
        # Return empty but valid response
        return Response({
            'success': True,
            'total_users_protected': 0,
            'verified_reports': 0,
            'top_scam_type': 'No scams detected yet',
            'top_scam_count': 0,
            'scam_distribution': [],
            'total_scam_types': 0
        }, status=status.HTTP_200_OK)