import type { ReactElement } from "react";
import {
  DEMO_ACCOUNTS,
  SASDemoApp,
} from "../demo/SASDemoApp.js";

export interface StoryMeta<TProps> {
  title: string;
  component: (props: TProps) => ReactElement;
}

export interface StoryObj<TProps> {
  name: string;
  args: TProps;
  render: (args: TProps) => ReactElement;
}

const meta: StoryMeta<Parameters<typeof SASDemoApp>[0]> = {
  title: "SorobanSAS/HooksDemo",
  component: SASDemoApp,
};

export default meta;

export const DefaultTestnetStory: StoryObj<Parameters<typeof SASDemoApp>[0]> = {
  name: "Testnet (Alice Connected)",
  args: {
    initialNetwork: "testnet",
    initialAccount: DEMO_ACCOUNTS.ALICE,
  },
  render: (args) => <SASDemoApp {...args} />,
};

export const LocalNetworkBobStory: StoryObj<Parameters<typeof SASDemoApp>[0]> = {
  name: "Local Network (Bob Connected)",
  args: {
    initialNetwork: "local",
    initialAccount: DEMO_ACCOUNTS.BOB,
  },
  render: (args) => <SASDemoApp {...args} />,
};
