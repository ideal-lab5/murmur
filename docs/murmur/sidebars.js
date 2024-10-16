/**
 * Creating a sidebar enables you to:
 - create an ordered group of docs
 - render a sidebar for each doc of that group
 - provide next/previous navigation

 The sidebars can be generated from the filesystem, or explicitly defined here.

 Create as many sidebars as you want.
 */

// @ts-check

/** @type {import('@docusaurus/plugin-content-docs').SidebarsConfig} */
const sidebars = {
  // By default, Docusaurus generates a sidebar from the docs folder structure
  docsSidebar: [{type: 'autogenerated', dirName: '.'}],

  // But you can create a sidebar manually
  customSidebar: [
    'intro',
    {
      type: 'category',
      label: 'Quick Start',
      items: ['quick_start/overview',
              'quick_start/local',
              'quick_start/browser',
              'quick_start/discord',
            ],
    },
    {
      type: 'category',
      label: 'Learn',
      items: ['learn/protocol'],
    },
  ],
};

export default sidebars;