// CyberSentinel SVG Circular Score Gauge
function updateScoreGauge(score, grade) {
  const circle = document.getElementById("gauge-circle");
  const scoreText = document.getElementById("gauge-score-value");
  const gradeBadge = document.getElementById("grade-badge");

  if (!circle || !scoreText) return;

  const radius = circle.r.baseVal.value;
  const circumference = 2 * Math.PI * radius;

  circle.style.strokeDasharray = `${circumference} ${circumference}`;

  // Color mapping based on score
  let strokeColor = "#10b981"; // Emerald
  let gradeClass = "a";

  if (score >= 95) {
    strokeColor = "#10b981";
    gradeClass = "a-plus";
  } else if (score >= 85) {
    strokeColor = "#34d399";
    gradeClass = "a";
  } else if (score >= 70) {
    strokeColor = "#3b82f6";
    gradeClass = "b";
  } else if (score >= 55) {
    strokeColor = "#f59e0b";
    gradeClass = "c";
  } else if (score >= 40) {
    strokeColor = "#fb923c";
    gradeClass = "d";
  } else {
    strokeColor = "#f43f5e";
    gradeClass = "f";
  }

  circle.style.stroke = strokeColor;

  // Animate offset
  const offset = circumference - (score / 100) * circumference;
  circle.style.strokeDashoffset = offset;

  // Animate score counter
  let current = 0;
  const duration = 1000;
  const stepTime = 15;
  const steps = duration / stepTime;
  const increment = score / steps;

  const counter = setInterval(() => {
    current += increment;
    if (current >= score) {
      current = score;
      clearInterval(counter);
    }
    scoreText.textContent = Math.round(current);
  }, stepTime);

  // Update grade badge
  if (gradeBadge) {
    gradeBadge.textContent = `GRADE ${grade}`;
    gradeBadge.className = `grade-badge ${gradeClass}`;
  }
}
