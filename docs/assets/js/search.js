---
---
(function() {
  var idx = null;
  var documents = [];
  var searchInput = document.getElementById('search-input');
  var searchResults = document.getElementById('search-results');

  if (!searchInput) return;

  // Build search index from page metadata
  var pages = [
    {% for p in site.pages %}
    {% if p.title and p.url != '/404.html' %}
    {
      title: {{ p.title | jsonify }},
      url: {{ p.url | jsonify }},
      description: {{ p.description | default: '' | jsonify }},
      content: {{ p.content | strip_html | normalize_whitespace | truncate: 5000 | jsonify }}
    },
    {% endif %}
    {% endfor %}
    {% for post in site.posts %}
    {
      title: {{ post.title | jsonify }},
      url: {{ post.url | jsonify }},
      description: {{ post.description | default: '' | jsonify }},
      content: {{ post.content | strip_html | normalize_whitespace | truncate: 5000 | jsonify }}
    },
    {% endfor %}
    {% for tutorial in site.tutorials %}
    {
      title: {{ tutorial.title | jsonify }},
      url: {{ tutorial.url | jsonify }},
      description: {{ tutorial.description | default: '' | jsonify }},
      content: {{ tutorial.content | strip_html | normalize_whitespace | truncate: 5000 | jsonify }}
    },
    {% endfor %}
  ];

  documents = pages;

  idx = lunr(function() {
    this.ref('url');
    this.field('title', { boost: 10 });
    this.field('description', { boost: 5 });
    this.field('content');

    pages.forEach(function(page) {
      this.add(page);
    }, this);
  });

  searchInput.addEventListener('input', function() {
    var query = this.value.trim();
    if (query.length < 2) {
      searchResults.innerHTML = '';
      searchResults.style.display = 'none';
      return;
    }

    try {
      var results = idx.search(query);
      var html = '';

      if (results.length === 0) {
        html = '<p class="search-no-results">No results found.</p>';
      } else {
        html = '<ul class="search-results-list">';
        results.slice(0, 10).forEach(function(result) {
          var doc = documents.find(function(d) { return d.url === result.ref; });
          if (doc) {
            html += '<li>';
            html += '<a href="' + doc.url + '">' + doc.title + '</a>';
            if (doc.description) {
              html += '<p class="search-result-desc">' + doc.description.substring(0, 150) + '</p>';
            }
            html += '</li>';
          }
        });
        html += '</ul>';
      }

      searchResults.innerHTML = html;
      searchResults.style.display = 'block';
    } catch(e) {
      searchResults.innerHTML = '';
    }
  });

  document.addEventListener('click', function(e) {
    if (!searchInput.contains(e.target) && !searchResults.contains(e.target)) {
      searchResults.style.display = 'none';
    }
  });
})();
