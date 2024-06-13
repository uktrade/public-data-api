'''
Usage: (use on at least an 8 core machine)

locust -f migration/test_load.py --users 200 --spawn-rate 20 --processes 8 -H https://data.api.trade.gov.uk
'''

from locust import FastHttpUser, task

class BasicUser(FastHttpUser):
    @task
    def root(self):
        self.client.get("/")

    @task
    def metadata_file(self):
        self.client.get("/v1/datasets/uk-tariff-2021-01-01/versions/v4.0.246/metadata?format=html")

    # @task
    # def download(self):
    #     with self.client.get("/v1/datasets/uk-tariff-2021-01-01/versions/v4.0.246/data?format=sqlite&download", stream=True) as r:
    #         for chunk in r.iter_content(chunk_size=65536):
    #             pass
