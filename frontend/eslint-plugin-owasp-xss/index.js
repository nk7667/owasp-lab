const MSG_REACT =
  '禁止直接使用 dangerouslySetInnerHTML；请改用 <SafeHtml value={sanitizeToSafeHtml(raw)} /> 或其它安全替代 API。';
const MSG_DOM =
  '禁止直接赋值 innerHTML/outerHTML；请改用安全替代 API（例如 mountSafeHtml / textContent / DOM API）。';

function hasAllowComment(node, sourceCode) {
  const comments = sourceCode.getCommentsBefore(node) || [];
  return comments.some((c) => String(c.value || '').includes('owasp-xss:allow'));
}

export default {
  rules: {
    'no-dangerously-set-inner-html': {
      meta: { type: 'problem', docs: { description: MSG_REACT } },
      create(context) {
        const sourceCode = context.getSourceCode();
        return {
          JSXAttribute(node) {
            if (node?.name?.name !== 'dangerouslySetInnerHTML') return;
            if (hasAllowComment(node, sourceCode)) return;
            context.report({ node, message: MSG_REACT });
          },
        };
      },
    },

    'no-innerhtml-assign': {
      meta: { type: 'problem', docs: { description: MSG_DOM } },
      create(context) {
        const sourceCode = context.getSourceCode();
        return {
          AssignmentExpression(node) {
            if (hasAllowComment(node, sourceCode)) return;
            const left = node.left;
            if (!left || left.type !== 'MemberExpression') return;
            if (left.computed) return; // 避免误伤 obj['innerHTML'] 之类的教学代码
            const prop = left.property;
            const name = prop && prop.type === 'Identifier' ? prop.name : null;
            if (name !== 'innerHTML' && name !== 'outerHTML') return;
            context.report({ node, message: MSG_DOM });
          },
        };
      },
    },
  },
};

