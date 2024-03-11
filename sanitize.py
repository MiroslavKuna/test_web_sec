"""HTML sanitizer for Gruyere, a web application with holes.

Copyright 2017 Google Inc. All rights reserved.

This code is licensed under the https://creativecommons.org/licenses/by-nd/3.0/us/
Creative Commons Attribution-No Derivative Works 3.0 United States license.

DO NOT COPY THIS CODE!

This application is a small self-contained web application with numerous
security holes. It is provided for use with the Web Application Exploits and
Defenses codelab. You may modify the code for your own use while doing the
codelab but you may not distribute the modified code. Brief excerpts of this
code may be used for educational or instructional purposes provided this
notice is kept intact. By using Gruyere you agree to the Terms of Service
https://www.google.com/intl/en/policies/terms/
"""

__author__ = 'Bruce Leban'

import hashlib
import re
import time


def SanitizeHtml(s):
  """Makes html safe for embedding in a document.

  Filters the html to exclude all but a small subset of html by
  removing script tags/attributes.

  Args:
    s: some html to sanitize.

  Returns:
    The html with all unsafe html removed.
  """
  processed = ''
  while s:
    start = s.find('<')
    if start >= 0:
      end = s.find('>', start)
      if end >= 0:
        before = s[:start]
        tag = s[start:end+1]
        after = s[end+1:]
      else:
        before = s[:start]
        tag = s[start:]
        after = ''
    else:
      before = s
      tag = ''
      after = ''

    processed += before + _SanitizeTag(tag)
    s = after
  return processed


TAG_RE = re.compile(r'<(.*?)(\s|>)')  # matches the start of an html tag


def _SanitizeTag(t):
  """Sanitizes a single html tag.

  This does both a 'whitelist' for
  the allowed tags and a 'blacklist' for the disallowed attributes.

  Args:
    t: a tag to sanitize.

  Returns:
    a safe tag.
  """
  allowed_tags = [
      'a', 'b', 'big', 'br', 'center', 'code', 'em', 'h1', 'h2', 'h3',
      'h4', 'h5', 'h6', 'hr', 'i', 'img', 'li', 'ol', 'p', 's', 'small',
      'span', 'strong', 'table', 'td', 'tr', 'u', 'ul',
  ]
  disallowed_attributes = [
      'onblur', 'onchange', 'onclick', 'ondblclick', 'onfocus',
      'onkeydown', 'onkeypress', 'onkeyup', 'onload', 'onmousedown',
      'onmousemove', 'onmouseout', 'onmouseover' 'onmouseup', 'onreset',
      'onselect', 'onsubmit', 'onunload'
  ]

  # Extract the tag name and make sure it's allowed.
  if t.startswith('</'):
    return t
  m = TAG_RE.match(t)
  if m is None:
    return t
  tag_name = m.group(1)
  if tag_name not in allowed_tags:
    t = t[:m.start(1)] + 'blocked' + t[m.end(1):]

  if t.__contains__('<script>') or t.__contains__('<script '):
    t = t[:m.start(1)] + 'blocked' + t[m.end(1):]

  for a in disallowed_attributes.casefold():
    t = t.replace(a, 'blocked')
  return t


def _PreventReflectedXss(s):
    return s.replace('<', '&lt;').replace('>', '&gt;')

def _GenerateXsrfToken(cookie, cookie_secret, action):
  timestamp = str(int(time.time()))
  token_data = f"{timestamp}|{action}|{cookie}"
  hash_value = hashlib.sha256((cookie_secret + token_data).encode()).hexdigest()
  return f"{timestamp}|{hash_value}"


def _VerifyXsrfToken(cookie, cookie_secret, action_token):
  try:
    action_time, action_hash = action_token.split("|", 1)
    token_data = f"{action_time}|{cookie}"
    expected_hash = hashlib.sha256((cookie_secret + token_data).encode()).hexdigest()

    if int(action_time) < time.time() - 86400 or action_hash != expected_hash:
      return False

    return True
  except (ValueError, IndexError):
    return False