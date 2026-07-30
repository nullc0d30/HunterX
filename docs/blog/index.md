---
layout: default
title: Blog — HunterX Technical Articles
description: >-
  Technical articles, tutorials, and updates about HunterX — the open-source
  AI-assisted vulnerability scanner. Red Team tips, bug bounty techniques,
  and security research.
---

## Blog

## Latest Posts

<ul>
{% for post in site.posts limit:10 %}
  <li>
    <a href="{{ post.url | relative_url }}">{{ post.title }}</a>
    <small>{{ post.date | date: "%b %d, %Y" }}</small>
    {% if post.description %}
    <p>{{ post.description | truncate: 200 }}</p>
    {% endif %}
  </li>
{% endfor %}
</ul>

## Categories

- [Red Team]({{ '/blog/category/red-team' | relative_url }})
- [Bug Bounty]({{ '/blog/category/bug-bounty' | relative_url }})
- [Technical]({{ '/blog/category/technical' | relative_url }})
- [Releases]({{ '/blog/category/releases' | relative_url }})

## RSS Feed

Subscribe: [feed.xml](feed.xml)
