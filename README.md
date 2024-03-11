# Test Web Security

!VŠECHNY ZMĚNY JSOU V SANITIZE.PY!

# Stored XSS
Upravil jsem funkci _SanitizeTag() několik věcí

1. Do disallowed_attributes jsem přidal 'onmouseover', lze přes něj zapínat scripty
2. Při prohledávání listu nastávaly problémy kvůli case sentitivity. Proto jsem udělat disallowed_attributes.casefold() - každý prvek je case insensitive.
3. přidal jsem if statement, který hlídá, zda se kdekoliv v tagu vyskytuje '<script>', nebo '<script'

# ReflectedXSS
Pro zabránění ReflectedXSS jsem vytvořil classu, co z inputlého stringu replacene všechny '<', '>' za jejich entitní názvy "&lt;" a "&gt;". Nijak to nezmění odkaz(protože se symboly mění automaticky na entitní jména), ale HTML už to nepřečte jako tagy.

# XSRF
Pro zabráňění XSRF útoků, potřebujeme způsob, jak zjistit, že daný request udělal opravdu připojený uživatel a ne útočník. Proto generujeme unikátní tokeny v moment zaznamenání requestu, které vygenerujeme pomocí timestampu a zahashovaných dat o akci. Po zpracování requestu se token vygeneruje znovu a zkontroluje se, zda sedí s prvním tokenem (s nějakou časovou tolerancí). Pro základ jsem použil classy z tohoto odkazu https://google-gruyere.appspot.com/part3#3__cross_site_request_forgery. Tam se ale token generoval pouze časem a cookie, nebere se ohled na akci provedenou uživatelem. 
