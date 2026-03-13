from sentry_plugins.client import ApiClient


class WebhookApiClient(ApiClient):
    plugin_name = "webhook"
    allow_redirects = False
    metrics_prefix = "integrations.webhook"

    def __init__(self, data, verify_ssl: bool = True):
        self.data = data
        super().__init__(verify_ssl=verify_ssl)

    def request(self, url):
        return self._request(
            path=url,
            method="post",
            data=self.data,
            json=True,
            timeout=5,
            allow_text=True,
            ignore_webhook_errors=True,
        )
