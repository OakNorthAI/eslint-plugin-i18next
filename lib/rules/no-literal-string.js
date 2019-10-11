/**
 * @fileoverview disallow literal string
 * @author edvardchen
 */
'use strict';

const {
  isUpperCase
} = require('../helper');
// const { TypeFlags, SyntaxKind } = require('typescript');

//------------------------------------------------------------------------------
// Rule Definition
//------------------------------------------------------------------------------

module.exports = {
  meta: {
    docs: {
      description: 'disallow literal string',
      category: 'Best Practices',
      recommended: true
    },
    schema: [{
      type: 'object',
      properties: {
        ignore: {
          type: 'array',
          items: {
            type: 'string'
          }
        },
        ignoreCallee: {
          type: 'array',
          items: {
            type: 'string'
          }
        },
        ignoreProperties: {
          type: 'array',
          items: {
            type: 'string'
          }
        },
        ignoreTags: {
          type: 'array',
          items: {
            type: 'object',
            properties: {
              tag: {
                anyOf: [{
                  type: 'string', // TODO: think about allowing array of strings alternatively.
                }, {
                  type: 'array',
                  items: {
                    type: 'string'
                  }
                }]
              },
              attributes: {
                type: 'array',
                items: {
                  type: 'string'
                }
              }
            }
          }
        }
      },
      additionalProperties: false
    }]
  },

  create: function (context) {
    // variables should be defined here
    const {
      parserServices,
      options: [option]
    } = context;
    const whitelists = ((option && option.ignore) || []).map(
      item => new RegExp(item)
    );
    const propWhitelist = (option && option.ignoreProperties) || [];
    const tagAttrWhiteList = ((option && option.ignoreTags) || []).map(entry =>
      ({ tags: typeof entry.tag === 'string' ? [entry.tag] : entry.tag,
         attributes: entry.attributes }));

    const calleeWhitelists = generateCalleeWhitelists(option);
    const translatorCalleeWhitelists = generateTranslatorWhitelists(option);
    //----------------------------------------------------------------------
    // Helpers
    //----------------------------------------------------------------------
    function match(str) {
      return whitelists.some(item => item.test(str));
    }

    function isTranlationFunctionCall({
      callee
    }) {
      let calleeName = callee.name;

      if (callee.type === 'MemberExpression') {
        if (translatorCalleeWhitelists.simple.indexOf(callee.property.name) !== -1)
          return true;

        calleeName = `${callee.object.name}.${callee.property.name}`;
        if (translatorCalleeWhitelists.complex.indexOf(calleeName) !== -1) return true;

        // Allow: socket.on to match this.socket.on or socket.on
        // Don't Allow: socket.on to match xsocket.on or this.xsocket.on
        calleeName = "." + context.getSourceCode().getText(callee);
        return translatorCalleeWhitelists.complex.some((c) => calleeName.endsWith("." + c))
      }
      return translatorCalleeWhitelists.simple.indexOf(calleeName) !== -1;
    }

    function isTechnicalFunctionCall({
      callee
    }) {
      // if(callee.type === 'TaggedTemplateExpression') return true;

      let calleeName = callee.name;
      if (callee.type === 'Import') return true;

      if (callee.type === 'MemberExpression') {
        if (calleeWhitelists.simple.indexOf(callee.property.name) !== -1)
          return true;

        calleeName = `${callee.object.name}.${callee.property.name}`;
        if (calleeWhitelists.complex.indexOf(calleeName) !== -1) return true;

        // Allow: socket.on to match this.socket.on or socket.on
        // Don't Allow: socket.on to match xsocket.on or this.xsocket.on
        calleeName = "." + context.getSourceCode().getText(callee);
        return calleeWhitelists.complex.some((c) => calleeName.endsWith("." + c))
      }

      if (calleeName === 'require') return true;

      return calleeWhitelists.simple.indexOf(calleeName) !== -1;
    }

    //----------------------------------------------------------------------
    // Public
    //----------------------------------------------------------------------
    const visited = new WeakSet();
    const translationNodes = new WeakSet();
    const technicalNodes = new WeakSet();
    const complaints = new Map();

    function getNearestAncestor(node, type) {
      let temp = node.parent;
      while (temp) {
        if (temp.type === type) {
          return temp;
        }
        temp = temp.parent;
      }
      return temp;
    }

    function checkTechnicalParents(node) {
      return context.getAncestors(node).some(x => technicalNodes.has(x));
    }
    function checkTranslationParents(node) {
      return context.getAncestors(node).some(x => translationNodes.has(x));
    }

    function isString(node) {
      return typeof node.value === 'string' || node.type === 'TemplateLiteral';
    }

    const {
      esTreeNodeToTSNodeMap,
      program
    } = parserServices;
    let typeChecker;
    if (program && esTreeNodeToTSNodeMap)
      typeChecker = program.getTypeChecker();

    const scriptVisitor = {
      //
      // ─── EXPORT AND IMPORT ───────────────────────────────────────────
      //

      'ImportDeclaration :matches(Literal, TemplateLiteral)'(node) {
        // allow (import abc form 'abc')
        visited.add(node);
      },

      'ExportAllDeclaration :matches(Literal, TemplateLiteral)'(node) {
        // allow export * from 'mod'
        visited.add(node);
      },

      'ExportNamedDeclaration > :matches(Literal, TemplateLiteral)'(node) {
        // allow export { named } from 'mod'
        visited.add(node);
      },
      // ─────────────────────────────────────────────────────────────────

      //
      // ─── JSX ─────────────────────────────────────────────────────────
      //

      'JSXElement > JSXOpeningElement'(node) {
        const name = context.getSourceCode().getText(node.name);
        if (name === "Trans" || name === "Translation") {
          translationNodes.add(node.parent);
        }
      },
      'JSXElement > :matches(Literal, TemplateLiteral)'(node) {
        scriptVisitor.JSXText(node);
      },

      'JSXAttribute'(node) {
        // allow <div className="active" />
        const element = getNearestAncestor(node, 'JSXOpeningElement');
        if (element !== null) {
          if (tagAttrWhiteList.some(entry =>
            (entry.tags.includes('*') || entry.tags.includes(element.name.name)) && entry.attributes.includes(node.name.name)
            )) {
              technicalNodes.add(node);
            }
        }
      },

      // ─────────────────────────────────────────────────────────────────

      //
      // ─── TYPESCRIPT ──────────────────────────────────────────────────
      //


      'TSModuleDeclaration :matches(Literal, TemplateLiteral)'(node) {
        // allow: declare module 'i18next-pseudo';
        visited.add(node);
      },
      'TSEnumDeclaration :matches(Literal, TemplateLiteral)'(node) {
        // allow:
        // export enum DialogKind {
        //   Closed = 'Closed',
        //   New = 'New',
        //   Edit = 'Edit',
        // }
        visited.add(node);
      },

      'TSLiteralType :matches(Literal, TemplateLiteral)'(node) {
        // allow var a: Type['member'];
        visited.add(node);
      },
      // ─────────────────────────────────────────────────────────────────

      'VariableDeclarator > :matches(Literal, TemplateLiteral)'(node) {
        // allow statements like const A_B = "test"
        if (isUpperCase(node.parent.id.name)) visited.add(node);
      },

      'TSAsExpression > :matches(Literal, TemplateLiteral)'(node) {
        // Allow: "test" as string
        // Allow: "test" as some_type
        visited.add(node);
      },
      'Property :matches(Literal, TemplateLiteral)'(node) {
        if (!isString(node)) return;
        const parent = getNearestAncestor(node, 'Property');

        // if node is key of property, skip
        if (parent.key === node) {
          visited.add(node);
          return;
        }

        if (typeof node.value === 'string') {
          const trimmed = node.value.trim();
          if (!trimmed || match(trimmed)) return;
        }

        if (propWhitelist.includes(parent.key.name)) visited.add(node);
        // name if key is Identifier; value if key is Literal
        // dont care whether if this is computed or not
        else if (isUpperCase(parent.key.name || parent.key.value)) visited.add(node);
        else {
          complaints.set(node, {
            node,
            message: "Forbidden literal assigned to property: {{ code }}",
            data: {
              code: context.getSourceCode().getText(parent),
            },
          });
        }
      },

      'BinaryExpression > :matches(Literal, TemplateLiteral)'(node) {
        const {
          parent: {
            operator
          }
        } = node;

        // allow: name === 'Android'
        if (operator !== '+') {
          visited.add(node);
        }
      },

      'TaggedTemplateExpression'(node) {
        const name =
          node.tag.type === 'CallExpression'
          ? node.tag.callee.name
          : node.tag.type === 'Identifier'
          ? node.tag.name
          : undefined;
        if (name === undefined) return;

        // TODO: stick into options.
        const translationTags = ['t', 'T'];
        if (translationTags.includes(name)) {
          translationNodes.add(node);
        }
      },
      'CallExpression'(node) {
        if (isTranlationFunctionCall(node)) translationNodes.add(node);
        if (isTechnicalFunctionCall(node)) technicalNodes.add(node);
      },

      'SwitchCase > :matches(Literal, TemplateLiteral)'(node) {
        visited.add(node);
      },

      ':matches(Literal, TemplateLiteral, JSXText):exit'(node) {
        if (!isString(node)) return;
        // visited and passed linting
        if (visited.has(node)) return;

        if (checkTranslationParents(node)) {
          const regex = /\$\{[^}]+\}/u;
          if (node.type === 'TemplateLiteral' && regex.test(context.getSourceCode().getText(node))) {
            complaints.set(node, {
              node,
              message: "Forbidden template literal placeholder ${} in translation string, use {{}} instead: {{ code }}",
              data: {
                code: context.getSourceCode().getText(node),
              },
            });
          } else {
            return;
          }
        }
        if (checkTechnicalParents(node)) return;
        if (typeof node.value === 'string') {
          const trimmed = node.value.trim();
          if (!trimmed) return;

          // allow statements like const a = "FOO"
          if (isUpperCase(trimmed)) return;

          if (match(trimmed)) return;
        }

        //
        // TYPESCRIPT
        //

        // TODO: Add support for allowing things like:
        // var a:  'abc' | 'name' = 'abc';
        // var a: 'abc' = 'abc';
        // without also allowing things like:
        // const a = condition ? 'abc' | 'cde';
        // The original upstream implementation allowed the latter.

        // Another example:
        // const d: (t: i18next.TFunction) => { [K in Field]: string } = (t) => ({
        //   field1: ("This used to be allowed when it shouldn't."),
        //   field2: "This was properly complained about.",
        // });

        // • • • • •

        {
          const element = getNearestAncestor(node, 'JSXOpeningElement');
          const attribute = getNearestAncestor(node, 'JSXAttribute');
          if (element !== null) {
            complaints.set(node, {
              node,
              message: "Forbidden literal string {{string}} as value for attribute '{{attribute}}' for tag '{{tag}}' in {{ code }} ",
              data: {
                string: context.getSourceCode().getText(node),
                attribute: attribute.name.name,
                tag: element.name.name,
                code: context.getSourceCode().getText(element),
              },
            });
          }
        }
        context.report(
          complaints.has(node) ?
          complaints.get(node) :
          {
            node,
            message: "Forbidden literal string {{string}} in {{ code }}.\nTypes: {{t}} {{ ptype }}",
            data: {
              string: context.getSourceCode().getText(node),
              code: context.getSourceCode().getText(node.parent),
              t: node.type,
              ptype: JSON.stringify(context.getAncestors(node).map(n => n.type).slice().reverse()),
            },
          });
      },
    };

    return (
      (parserServices.defineTemplateBodyVisitor &&
        parserServices.defineTemplateBodyVisitor({
            VText(node) {
              scriptVisitor['JSXText'](node);
            },
            'VExpressionContainer CallExpression :matches(Literal, TemplateLiteral)'(node) {
              scriptVisitor['CallExpression :matches(Literal, TemplateLiteral)'](node);
            },
            'VExpressionContainer :matches(Literal, TemplateLiteral):exit'(node) {
              scriptVisitor[':matches(Literal, TemplateLiteral):exit'](node);
            }
          },
          scriptVisitor
        )) ||
      scriptVisitor
    );
  }
};

const popularCallee = [
  'addEventListener',
  //
  // ─── VUEX CALLEE ────────────────────────────────────────────────────────────────
  //
  'dispatch',
  'commit',
  // ────────────────────────────────────────────────────────────────────────────────

  'includes',
  'indexOf'
];

function generateTranslatorWhitelists(option) {
  const ignoreCallee = (option && option.ignoreTranslatorCallee) || [];
  const result = {
    simple: ['i18n', 'i18next', 't', 'T'],
    complex: ['i18n.t', 'i18next.t']
  };
  ignoreCallee.forEach(item => {
    if (item.indexOf('.') !== -1) {
      result.complex.push(item);
    } else {
      result.simple.push(item);
    }
  });
  return result;
}

function generateCalleeWhitelists(option) {
  const ignoreCallee = (option && option.ignoreCallee) || [];
  const result = {
    simple: [...popularCallee],
    complex: []
  };
  ignoreCallee.forEach(item => {
    if (item.indexOf('.') !== -1) {
      result.complex.push(item);
    } else {
      result.simple.push(item);
    }
  });
  return result;
}
