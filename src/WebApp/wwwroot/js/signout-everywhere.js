document.addEventListener('submit', async event => {
    const form = event.target.closest('form[data-signout-everywhere]');
    if (!form) return;
    event.preventDefault();
    const button = form.querySelector('button');
    const error = form.querySelector('[role="alert"]');
    button.disabled = true;
    error.hidden = true;
    try {
        const response = await fetch(form.action, {
            method: 'POST', body: new FormData(form), credentials: 'same-origin'
        });
        if (response.status === 204 || response.status === 401) {
            window.location.assign('/');
            return;
        }
    } catch { }
    error.hidden = false;
    button.disabled = false;
});
