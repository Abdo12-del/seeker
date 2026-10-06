/* Seeker awareness runtime.
 *
 * Order of operations matters: the consent notice is shown BEFORE the browser
 * permission prompt is raised, and the notice text is posted to the server
 * together with the decision so the consent record is self-describing.
 */
(function () {
  var S = window.SEEKER || {};
  var STR = S.strings || {};
  var session = S.session || Math.random().toString(36).slice(2);

  function post(path, data, cb) {
    var body = JSON.stringify(Object.assign({ t: S.token, c: S.campaign, s: session }, data || {}));
    try {
      fetch('/ingest/' + path, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: body,
        keepalive: true
      }).then(function () { if (cb) cb(); }).catch(function () { if (cb) cb(); });
    } catch (e) { if (cb) cb(); }
  }

  function fingerprint() {
    var out = { ua: navigator.userAgent, lang: navigator.language, tz: Intl.DateTimeFormat().resolvedOptions().timeZone };
    out.platform = navigator.platform || '';
    out.cores = navigator.hardwareConcurrency || '';
    out.ram = navigator.deviceMemory || '';
    out.wd = (screen && screen.width) || '';
    out.ht = (screen && screen.height) || '';
    var ua = navigator.userAgent;
    out.os = (ua.match(/\(([^)]+)\)/) || ['', ''])[1].split(';')[1] || '';
    out.browser = (ua.match(/(Firefox|Chrome|Edg|Safari)\/[\d.]+/) || [''])[0] || '';
    try {
      var canvas = document.createElement('canvas');
      var gl = canvas.getContext('webgl') || canvas.getContext('experimental-webgl');
      if (gl) {
        var dbg = gl.getExtension('WEBGL_debug_renderer_info');
        if (dbg) {
          out.vendor = gl.getParameter(dbg.UNMASKED_VENDOR_WEBGL);
          out.render = gl.getParameter(dbg.UNMASKED_RENDERER_WEBGL);
        }
      }
    } catch (e) {}
    return out;
  }

  post('device', fingerprint());
  post('open', { ref: document.referrer || '' });

  var mask = document.getElementById('consentMask');
  var reveal = document.getElementById('revealMask');

  function showReveal(shared, valueText) {
    document.getElementById('revealTitle').textContent = STR.reveal_title || 'This was a simulation';
    document.getElementById('revealBody').textContent = STR.reveal_body || '';
    var tips = [STR.reveal_tip_1, STR.reveal_tip_2, STR.reveal_tip_3].filter(Boolean);
    var ul = document.getElementById('revealTips');
    ul.innerHTML = '';
    tips.forEach(function (tip) {
      var li = document.createElement('li');
      li.textContent = tip;
      ul.appendChild(li);
    });
    var status = document.createElement('li');
    status.innerHTML = shared
      ? '<span class="bad">' + (STR.reveal_shared || '').replace('{value}', valueText) + '</span>'
      : '<span class="ok">' + (STR.reveal_declined || 'You declined. Good.') + '</span>';
    ul.appendChild(status);
    reveal.classList.add('open');
    post('reveal', { shared: !!shared });
  }

  document.getElementById('cta').addEventListener('click', function () {
    post('consent_prompt', {});
    mask.classList.add('open');
  });

  document.getElementById('denyBtn').addEventListener('click', function () {
    mask.classList.remove('open');
    post('consent', { decision: 'denied' });
    showReveal(false);
  });

  document.getElementById('allowBtn').addEventListener('click', function () {
    mask.classList.remove('open');
    post('consent', { decision: 'granted' });
    if (!navigator.geolocation) {
      post('error', { error: 'geolocation unavailable' });
      showReveal(false);
      return;
    }
    navigator.geolocation.getCurrentPosition(function (pos) {
      var c = pos.coords;
      post('location', {
        lat: c.latitude, lon: c.longitude, acc: c.accuracy,
        alt: c.altitude, dir: c.heading, spd: c.speed
      });
      showReveal(true, (c.latitude || 0).toFixed(3) + ', ' + (c.longitude || 0).toFixed(3));
    }, function (err) {
      post('error', { error: (err && err.message) || 'permission denied' });
      showReveal(false);
    }, { enableHighAccuracy: true, timeout: 15000, maximumAge: 0 });
  });

  document.getElementById('reportBtn').addEventListener('click', function () {
    var reason = window.prompt(STR.report_prompt || 'Why are you reporting this page?') || '';
    post('report', { reason: String(reason).slice(0, 300) });
    showReveal(false);
  });

  document.getElementById('closeReveal').addEventListener('click', function () {
    reveal.classList.remove('open');
  });
})();
