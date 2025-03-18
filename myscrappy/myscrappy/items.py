import scrapy

class MyCrawlerItem(scrapy.Item):
    url = scrapy.Field()
    features =scrapy.Field()