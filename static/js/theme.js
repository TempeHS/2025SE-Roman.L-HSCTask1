document.addEventListener('DOMContentLoaded', function () {
    document.body.dataset.bsTheme = localStorage.getItem('theme') || 'light';
    document.getElementById('flexSwitchCheckChecked').checked = document.body.dataset.bsTheme === 'dark';

    // Attach event listener for dark mode toggle
    document.getElementById('flexSwitchCheckChecked').addEventListener('click', darkMode);
});

// Bootstrap dark mode
function darkMode() {
    const newTheme = document.body.dataset.bsTheme === "dark" ? "light" : "dark";
    document.body.dataset.bsTheme = newTheme;
    localStorage.setItem('theme', newTheme);
    document.getElementById('flexSwitchCheckChecked').checked = newTheme === 'dark';
}