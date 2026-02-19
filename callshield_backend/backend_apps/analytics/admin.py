from django.contrib import admin

# This app has no models, so no admin registration needed.
# Analytics are computed on-the-fly from other apps' models.

# Admin can view analytics through the API endpoints:
# - GET /api/analytics/admin/overview/
# - GET /api/analytics/admin/activity/
# - GET /api/analytics/admin/trends/
# - GET /api/analytics/admin/engagement/

