---
layout: default
title: Release Announcements — HunterX Blog
description: >-
  HunterX release notes and announcements. Version updates, new features,
  breaking changes, and migration guides.
---

## Release Announcements

<ul>
{% for post in site.posts %}
  {% if post.categories contains "releases" %}
  <li>
    <a href="{{ post.url | relative_url }}">{{ post.title }}</a>
    <small>{{ post.date | date: "%b %d, %Y" }}</small>
    <p>{{ post.description | truncate: 200 }}</p>
  </li>
  {% endif %}
{% endfor %}
</ul>

[Back to Blog]({{ '/blog' | relative_url }})
