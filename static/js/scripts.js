const searchForm = document.getElementById("search-form");
const searchInput = document.getElementById("search-input");
const results = document.getElementById("results");

searchForm.addEventListener("submit", (e) => {
  e.preventDefault();
  if (!searchInput.value.trim()) {
    alert("Please enter a gene or disease name.");
    return;
  }
  results.style.display = "block";
  results.innerHTML = `<p>Searching for "${searchInput.value.trim()}"...</p>`;
  // Here you can implement the functionality to fetch and display the relevant information
});
