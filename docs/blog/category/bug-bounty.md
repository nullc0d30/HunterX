---
layout: default
title: Bug Bounty Articles — HunterX Blog
description: >-
  Bug bounty hunting guides and workflows using HunterX. Profiled scanning,
  safe testing practices, and integration with bug bounty toolchains.
---

# Bug Bounty Articles

<ul>
{% for post in site.posts %}
  {% if post.categories contains "bug-bounty" %}
  <li>
    <a href="{{ post.url | relative_url }}">{{ post.title }}</a>
    <small>{{ post.date | date: "%b %d, %Y" }}</small>
    <p>{{ post.description | truncate: 200 }}</p>
  </li>
  {% endif %}
{% endfor %}
</ul>

[Back to Blog]({{ '/blog' | relative_url }})
