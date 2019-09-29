#!/usr/bin/python3
from concurrent.futures import ThreadPoolExecutor
from bs4 import BeautifulSoup
from requests import Session
from urllib.parse import urljoin
from random import sample
from pymongo import MongoClient

pool = ThreadPoolExecutor(max_workers=256)
s = Session()

client = MongoClient()
coll = client["wasm2"]["sites"]


def crawl_site(site_id, base_url):
    try:
        urls = set()
        resp = s.get(base_url, timeout=3)
        if not resp.ok:
            return
        if len(resp.history) >= 2:
            base_url = resp.history[-1].url
        soup = BeautifulSoup(resp.text)
        for e in soup.find_all("a"):
            if e.has_attr("href"):
                url = e.attrs["href"]
                if url.startswith("#") or url.lower().startswith("javascript:"):
                    continue
                full_url = urljoin(base_url, url)
                if full_url.startswith("http") and not full_url.rstrip("/") == base_url.rstrip("/"):
                    urls.add(full_url)
        if len(urls) > 3:
            urls = list(sample(urls, 3))
        else:
            urls = list(urls)
        return coll.insert({"site": base_url, "urls": urls})
    except Exception as e:
        print(e)


def main():
    with open("ok.txt") as f:
        for url in f:
            url = url.rstrip("\r\n/")
            site_id = url
            if coll.find_one({"site": site_id}):
                continue
            if not url.startswith("http"):
                url = "http://" + url
            pool.submit(crawl_site, site_id, url)


if __name__ == "__main__":
    main()
