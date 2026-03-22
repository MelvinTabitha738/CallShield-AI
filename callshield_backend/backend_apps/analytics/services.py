# backend_apps/analytics/services.py

from django.db.models import Count, Q, Avg, Sum
from django.utils import timezone
from datetime import timedelta
from backend_apps.authentication.models import User
from backend_apps.real_time_detection.models import (
    CallSession, RiskAlert, ConfirmedScamConversation
)
from backend_apps.scam_database.models import (
    PhoneNumberActive, PhoneNumberArchived, ScamIncident, ReporterCredibility
)
from backend_apps.real_time_detection.ml_integration import MLModelInterface


class UserAnalyticsService:
    """
    Analytics for individual users shown in their personal dashboard.
    """

    @classmethod
    def get_user_stats(cls, user):
        """
        Get comprehensive stats for a specific user.
        
        Returns all data needed for user's personal dashboard.
        """
        # Protection stats
        total_calls = CallSession.objects.filter(
            user=user,
            status='completed'
        ).count()

        scams_blocked = CallSession.objects.filter(
            user=user,
            status='completed',
            peak_risk_score__gte=70
        ).count()

        safe_calls = total_calls - scams_blocked

        success_rate = (
            (scams_blocked / total_calls * 100) if total_calls > 0 else 0
        )

        last_session = CallSession.objects.filter(
            user=user,
            status='completed'
        ).order_by('-ended_at').first()

        # Community contribution
        reports_submitted = ScamIncident.objects.filter(
            reported_by=user
        ).count()

        pending_reports_count  = ScamIncident.objects.filter(
            reported_by=user, verified=False
        ).count()
        verified_reports_count = ScamIncident.objects.filter(
            reported_by=user, verified=True
        ).count()

        # Report history — last 90 days, most recent first
        ninety_days_ago = timezone.now() - timedelta(days=90)
        recent_reports_qs = ScamIncident.objects.filter(
            reported_by=user,
            reported_at__gte=ninety_days_ago
        ).order_by('-reported_at')[:20]

        report_history = [
            {
                'id':          str(r.id),
                'scam_type':   r.scam_type,
                'status':      'verified' if r.verified else 'pending',
                'source':      r.source,
                'reported_at': r.reported_at.isoformat(),
                'severity':    r.severity,
            }
            for r in recent_reports_qs
        ]

        training_contributions = ConfirmedScamConversation.objects.filter(
            session__user=user,
            user_consented_training=True
        ).count()

        # Get reporter credibility
        try:
            credibility = ReporterCredibility.objects.get(user=user)
            community_score = int(credibility.credibility_score * 100) 
            badge = credibility.credibility_tier
        except ReporterCredibility.DoesNotExist:
            community_score = 0
            badge = 'new'

        # Training contributions — calls where user consented for AI training
        # This is concrete and accurate unlike hash-matching "users helped"
        training_contributions = ConfirmedScamConversation.objects.filter(
            session__user=user,
            user_consented_training=True
        ).count()

        # Call summary
        last_scam_session = CallSession.objects.filter(
            user=user,
            status='completed',
            peak_risk_score__gte=70
        ).order_by('-ended_at').first()

        most_recent_call = last_session
        most_recent_type = 'safe'
        if last_scam_session and last_session:
            if last_scam_session.ended_at > last_session.ended_at:
                most_recent_type = 'scam'

        # Recent activity (last 7 days)
        seven_days_ago = timezone.now() - timedelta(days=7)
        recent_activity = []

        for i in range(7):
            date = timezone.now().date() - timedelta(days=i)
            date_start = timezone.make_aware(
                timezone.datetime.combine(date, timezone.datetime.min.time())
            )
            date_end = timezone.make_aware(
                timezone.datetime.combine(date, timezone.datetime.max.time())
            )

            day_sessions = CallSession.objects.filter(
                user=user,
                status='completed',
                ended_at__gte=date_start,
                ended_at__lte=date_end
            )

            day_calls = day_sessions.count()
            day_scams = day_sessions.filter(peak_risk_score__gte=70).count()

            # Only include days that had actual call activity
            if day_calls > 0:
                recent_activity.append({
                    'date': date.isoformat(),
                    'calls': day_calls,
                    'scams': day_scams
                })

        # Scam types encountered
        scam_types = CallSession.objects.filter(
            user=user,
            status='completed',
            peak_risk_score__gte=70,
            detected_scam_type__isnull=False
        ).exclude(
            detected_scam_type=''
        ).values('detected_scam_type').annotate(
            count=Count('id')
        ).order_by('-count')

        scam_types_list = [
            {
                'type': item['detected_scam_type'],
                'count': item['count']
            }
            for item in scam_types
        ]

        most_common_scam = (
            scam_types_list[0]['type'] if scam_types_list else None
        )

        return {
            'protection': {
                'total_calls': total_calls,
                'scams_blocked': scams_blocked,
                'safe_calls': safe_calls,
                'success_rate': round(success_rate, 1),
                'last_protected_at': (
                    last_session.ended_at.isoformat() if last_session else None
                ),
                'member_since': user.created_at.isoformat(),
            },
            'calls_summary': {
                'scam_calls': scams_blocked,
                'safe_calls': safe_calls,
                'scam_percentage': round(
                    (scams_blocked / total_calls * 100) if total_calls > 0 else 0,
                    1
                ),
                'safe_percentage': round(
                    (safe_calls / total_calls * 100) if total_calls > 0 else 0,
                    1
                ),
                'most_recent_call': {
                    'type': most_recent_type,
                    'time': (
                        most_recent_call.ended_at.isoformat()
                        if most_recent_call else None
                    )
                },
                'last_scam_blocked': {
                    'type': (
                        last_scam_session.detected_scam_type
                        if last_scam_session else None
                    ),
                    'time': (
                        last_scam_session.ended_at.isoformat()
                        if last_scam_session else None
                    )
                }
            },
            'community': {
                'reports_submitted': verified_reports_count,
                'training_contributions': training_contributions,
                'community_score': community_score,
                'badge': badge,
                'impact_message': cls._get_impact_message(reports_submitted, training_contributions)
            },
            'recent_activity': recent_activity,
            'scam_types_encountered': scam_types_list,
            'most_common_scam': most_common_scam,
            'reports': {
                'pending':  pending_reports_count,
                'verified': verified_reports_count,
                'history':  report_history,
            }
        }

    @staticmethod
    def _get_impact_message(reports_submitted, training_contributions):
        """Generate impact message based on actual contributions."""
        if reports_submitted == 0:
            return "Submit a report to help protect the community."
        elif training_contributions == 0:
            if reports_submitted == 1:
                return "Your report is under review. Thank you for contributing!"
            else:
                return f"You've submitted {reports_submitted} reports. Keep it up!"
        elif training_contributions < 5:
            return f"Your data is helping train CallShield's AI model."
        elif training_contributions < 20:
            return f"Great work — {training_contributions} training contributions so far!"
        else:
            return f"Excellent! {training_contributions} AI training contributions."


class AdminAnalyticsService:
    """
    Analytics for admin dashboard.
    System-wide statistics and monitoring.
    """

    @classmethod
    def get_system_overview(cls):
        """Get high-level system statistics."""
        now = timezone.now()
        today_start = now.replace(hour=0, minute=0, second=0, microsecond=0)
        week_start = now - timedelta(days=7)
        month_start = now - timedelta(days=30)

        # User stats
        total_users = User.objects.count()
        active_today = CallSession.objects.filter(
            started_at__gte=today_start
        ).values('user').distinct().count()
        
        active_week = CallSession.objects.filter(
            started_at__gte=week_start
        ).values('user').distinct().count()
        
        active_month = CallSession.objects.filter(
            started_at__gte=month_start
        ).values('user').distinct().count()
        
        new_users_30_days = User.objects.filter(
            created_at__gte=month_start
        ).count()

        # Detection stats
        total_sessions = CallSession.objects.filter(
            status='completed'
        ).count()
        
        sessions_today = CallSession.objects.filter(
            status='completed',
            ended_at__gte=today_start
        ).count()
        
        scams_detected = CallSession.objects.filter(
            status='completed',
            peak_risk_score__gte=70
        ).count()
        
        detection_rate = (
            (scams_detected / total_sessions * 100)
            if total_sessions > 0 else 0
        )

        # Database stats
        active_numbers = PhoneNumberActive.objects.count()
        archived_numbers = PhoneNumberArchived.objects.count()
        total_reports = ScamIncident.objects.count()
        training_conversations = ConfirmedScamConversation.objects.filter(
            user_consented_training=True
        ).count()

        # ML Model info
        model_info = MLModelInterface.get_model_info()

        return {
            'users': {
                'total': total_users,
                'active_today': active_today,
                'active_week': active_week,
                'active_month': active_month,
                'new_30_days': new_users_30_days
            },
            'detection': {
                'total_sessions': total_sessions,
                'sessions_today': sessions_today,
                'scams_detected': scams_detected,
                'detection_rate': round(detection_rate, 1)
            },
            'database': {
                'active_numbers': active_numbers,
                'archived_numbers': archived_numbers,
                'total_reports': total_reports,
                'training_conversations': training_conversations
            },
            'ml_model': {
                'status': 'loaded' if model_info['ready'] else 'not_loaded',
                'version': model_info['version'],
                'ready': model_info['ready']
            }
        }

    @classmethod
    def get_time_based_activity(cls):
        """Get activity stats for today/week/month."""
        now = timezone.now()
        today_start = now.replace(hour=0, minute=0, second=0, microsecond=0)
        week_start = now - timedelta(days=7)
        month_start = now - timedelta(days=30)

        def get_period_stats(start_time):
            sessions = CallSession.objects.filter(
                status='completed',
                ended_at__gte=start_time
            )
            scams = sessions.filter(peak_risk_score__gte=70).count()
            reports = ScamIncident.objects.filter(
                reported_at__gte=start_time
            ).count()
            
            return {
                'sessions': sessions.count(),
                'scams': scams,
                'reports': reports
            }

        return {
            'today': get_period_stats(today_start),
            'week': get_period_stats(week_start),
            'month': get_period_stats(month_start)
        }

    @classmethod
    def get_scam_trends(cls):
        """Get scam type distribution and trends."""
        # Last 30 days
        thirty_days_ago = timezone.now() - timedelta(days=30)
        
        # Scam type distribution
        scam_types = CallSession.objects.filter(
            status='completed',
            peak_risk_score__gte=70,
            ended_at__gte=thirty_days_ago,
            detected_scam_type__isnull=False
        ).exclude(
            detected_scam_type=''
        ).values('detected_scam_type').annotate(
            count=Count('id')
        ).order_by('-count')

        total_scams = sum(item['count'] for item in scam_types)

        scam_distribution = [
            {
                'type': item['detected_scam_type'],
                'count': item['count'],
                'percentage': round(
                    (item['count'] / total_scams * 100) if total_scams > 0 else 0,
                    1
                )
            }
            for item in scam_types
        ]

        # Weekly trends (compare this week vs last week)
        now = timezone.now()
        this_week_start = now - timedelta(days=7)
        last_week_start = now - timedelta(days=14)

        this_week_types = CallSession.objects.filter(
            status='completed',
            peak_risk_score__gte=70,
            ended_at__gte=this_week_start,
            detected_scam_type__isnull=False
        ).exclude(
            detected_scam_type=''
        ).values('detected_scam_type').annotate(count=Count('id'))

        last_week_types = CallSession.objects.filter(
            status='completed',
            peak_risk_score__gte=70,
            ended_at__gte=last_week_start,
            ended_at__lt=this_week_start,
            detected_scam_type__isnull=False
        ).exclude(
            detected_scam_type=''
        ).values('detected_scam_type').annotate(count=Count('id'))

        # Calculate trends
        this_week_dict = {
            item['detected_scam_type']: item['count']
            for item in this_week_types
        }
        last_week_dict = {
            item['detected_scam_type']: item['count']
            for item in last_week_types
        }

        trending_up = []
        trending_down = []

        for scam_type in set(list(this_week_dict.keys()) + list(last_week_dict.keys())):
            this_week_count = this_week_dict.get(scam_type, 0)
            last_week_count = last_week_dict.get(scam_type, 0)

            if last_week_count > 0:
                change = ((this_week_count - last_week_count) / last_week_count * 100)
                if change > 10:
                    trending_up.append({
                        'type': scam_type,
                        'change': round(change, 1)
                    })
                elif change < -10:
                    trending_down.append({
                        'type': scam_type,
                        'change': round(abs(change), 1)
                    })

        return {
            'distribution': scam_distribution,
            'trending_up': trending_up,
            'trending_down': trending_down
        }

    @classmethod
    def get_user_engagement(cls):
        """Get user engagement metrics."""
        now = timezone.now()
        today_start = now.replace(hour=0, minute=0, second=0, microsecond=0)
        week_start = now - timedelta(days=7)
        month_start = now - timedelta(days=30)

        # DAU/WAU/MAU
        dau = CallSession.objects.filter(
            started_at__gte=today_start
        ).values('user').distinct().count()

        wau = CallSession.objects.filter(
            started_at__gte=week_start
        ).values('user').distinct().count()

        mau = CallSession.objects.filter(
            started_at__gte=month_start
        ).values('user').distinct().count()

        # Average sessions per user
        total_users = User.objects.count()
        total_sessions = CallSession.objects.filter(
            status='completed'
        ).count()
        avg_sessions = (
            (total_sessions / total_users) if total_users > 0 else 0
        )

        # Average reports per user
        total_reports = ScamIncident.objects.count()
        avg_reports = (
            (total_reports / total_users) if total_users > 0 else 0
        )

        # Training contributors
        training_contributors = ConfirmedScamConversation.objects.filter(
            user_consented_training=True
        ).values('session__user').distinct().count()
        
        contributor_percentage = (
            (training_contributors / total_users * 100)
            if total_users > 0 else 0
        )

        # Top contributors — use badge tier, never expose raw phone numbers
        top_contributors = ScamIncident.objects.values(
            'reported_by__id',
            'reported_by__phone_number_hash',
        ).annotate(
            report_count=Count('id')
        ).order_by('-report_count')[:5]

        top_list = [
            {
                'user_id': str(item['reported_by__id']),
                # Show only first 8 chars of hash as a safe public identifier
                'identifier': (item['reported_by__phone_number_hash'] or '')[:8] + '…',
                'reports': item['report_count'],
            }
            for item in top_contributors if item['reported_by__id']
        ]

        return {
            'dau': dau,
            'wau': wau,
            'mau': mau,
            'avg_sessions_per_user': round(avg_sessions, 1),
            'avg_reports_per_user': round(avg_reports, 1),
            'training_contributor_percentage': round(contributor_percentage, 1),
            'top_contributors': top_list
        }


class PublicAnalyticsService:
    """
    Analytics for public display (marketing website).
    No PII exposed.
    """

    @classmethod
    def get_community_impact(cls):
        """Get public community impact stats."""
        total_scams_blocked = CallSession.objects.filter(
            status='completed',
            peak_risk_score__gte=70
        ).count()

        total_users_protected = CallSession.objects.filter(
            status='completed'
        ).values('user').distinct().count()

        total_sessions = CallSession.objects.filter(
            status='completed'
        ).count()

        success_rate = (
            (total_scams_blocked / total_sessions * 100)
            if total_sessions > 0 else 0
        )

        # Active now (sessions in last hour)
        one_hour_ago = timezone.now() - timedelta(hours=1)
        active_now = CallSession.objects.filter(
            started_at__gte=one_hour_ago,
            status='active'
        ).count()

        # Today's stats
        today_start = timezone.now().replace(
            hour=0, minute=0, second=0, microsecond=0
        )
        calls_today = CallSession.objects.filter(
            status='completed',
            ended_at__gte=today_start
        ).count()

        scams_today = CallSession.objects.filter(
            status='completed',
            peak_risk_score__gte=70,
            ended_at__gte=today_start
        ).count()

        # Community strength
        total_reports = ScamIncident.objects.count()
        active_contributors = ScamIncident.objects.values(
            'reported_by'
        ).distinct().count()
        
        training_contributions = ConfirmedScamConversation.objects.filter(
            user_consented_training=True
        ).count()

        return {
            'total_scams_blocked': total_scams_blocked,
            'total_users_protected': total_users_protected,
            'success_rate': round(success_rate, 1),
            'active_now': active_now,
            'calls_today': calls_today,
            'scams_today': scams_today,
            'total_reports': total_reports,
            'active_contributors': active_contributors,
            'training_contributions': training_contributions
        }

    @classmethod
    def get_scam_intelligence(cls):
        """Get public scam type distribution (no PII)."""
        # Last 30 days
        thirty_days_ago = timezone.now() - timedelta(days=30)

        scam_types = CallSession.objects.filter(
            status='completed',
            peak_risk_score__gte=70,
            ended_at__gte=thirty_days_ago,
            detected_scam_type__isnull=False
        ).exclude(
            detected_scam_type=''
        ).values('detected_scam_type').annotate(
            count=Count('id')
        ).order_by('-count')

        total = sum(item['count'] for item in scam_types)

        distribution = [
            {
                'type': item['detected_scam_type'],
                'percentage': round(
                    (item['count'] / total * 100) if total > 0 else 0,
                    1
                )
            }
            for item in scam_types
        ]

        return {
            'distribution': distribution,
            'most_common': distribution[0]['type'] if distribution else None
        }