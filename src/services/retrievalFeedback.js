import { API_BASE_URL } from '../config';

export async function recordFindingFeedback({ projectName, threat, decision }) {
  const explanation = threat?.explanation || {};
  const provenance = explanation.retrieval_provenance || explanation.provenance || {};
  const response = await fetch(`${API_BASE_URL}/feedback/findings`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      project_name: projectName,
      finding_id: threat.id,
      decision,
      query: `${threat.title}. ${threat.description || ''}`,
      retrieval_score: Number(provenance.retrieval_score || 0),
      stride_category: threat.stride_category || threat.category,
      security_domains: provenance.security_domains || [],
      finding: {
        id: threat.id,
        rule_id: provenance.rule_id || null,
        title: threat.title,
        stride_category: threat.stride_category || threat.category,
        affected_components: threat.affected_components || [],
      },
    }),
  });
  if (!response.ok) throw new Error(`Feedback API error: ${response.status}`);
  return response.json();
}
