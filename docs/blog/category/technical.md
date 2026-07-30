---
layout: default
title: Technical Articles — HunterX Blog
description: >-
  In-depth technical articles about HunterX's architecture, pipeline, plugin
  system, and internals for security researchers and developers.
---

## Technical Articles

<ul>
{% for post in site.posts %}
  {% if post.categories contains "technical" %}
  <li>
    <a href="{{ post.url | relative_url }}">{{ post.title }}</a>
    <small>{{ post.date | date: "%b %d, %Y" }}</small>
    <p>{{ post.description | truncate: 200 }}</p>
  </li>
  {% endif %}
{% endfor %}
</ul>

[Back to Blog]({{ '/blog' | relative_url }})
