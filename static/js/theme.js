document.body.dataset.bsTheme = localStorage.getItem('theme') || 'dark';
document.getElementById('flexSwitchCheckChecked').checked = document.body.dataset.bsTheme === 'dark'

// bootstrap dark mode
function darkMode() {
    const newTheme = document.body.dataset.bsTheme == "dark" ? "light" : "dark";
    document.body.dataset.bsTheme = newTheme;
    localStorage.setItem('theme', newTheme);
    document.getElementById('flexSwitchCheckChecked').checked = newTheme === 'dark';
}