import { describe, it, expect, vi } from 'vitest';
import { render, fireEvent } from '@testing-library/svelte';
import Input from './Input.svelte';

describe('Input', () => {
  it('forwards oninput handler to the underlying input element', async () => {
    const handler = vi.fn();
    const { container } = render(Input, {
      props: { label: 'Token', oninput: handler },
    });

    const input = container.querySelector('input');
    expect(input).not.toBeNull();

    await fireEvent.input(input, { target: { value: 'test-token' } });
    expect(handler).toHaveBeenCalledTimes(1);
  });

  it('forwards onchange handler to the underlying input element', async () => {
    const handler = vi.fn();
    const { container } = render(Input, {
      props: { label: 'Field', onchange: handler },
    });

    const input = container.querySelector('input');
    await fireEvent.change(input, { target: { value: 'new-value' } });
    expect(handler).toHaveBeenCalledTimes(1);
  });

  it('forwards onblur handler to the underlying input element', async () => {
    const handler = vi.fn();
    const { container } = render(Input, {
      props: { label: 'Field', onblur: handler },
    });

    const input = container.querySelector('input');
    await fireEvent.blur(input);
    expect(handler).toHaveBeenCalledTimes(1);
  });

  it('renders label text', () => {
    const { container } = render(Input, {
      props: { label: 'Bot Token' },
    });

    const label = container.querySelector('label');
    expect(label.textContent).toBe('Bot Token');
  });

  it('applies disabled attribute', () => {
    const { container } = render(Input, {
      props: { disabled: true },
    });

    const input = container.querySelector('input');
    expect(input.disabled).toBe(true);
  });

  it('shows error text when error prop is set', () => {
    const { container } = render(Input, {
      props: { error: 'Required field' },
    });

    const errorEl = container.querySelector('.text-red-500, .text-red-400');
    expect(errorEl).not.toBeNull();
    expect(errorEl.textContent).toBe('Required field');
  });

  it('shows help text when no error', () => {
    const { container } = render(Input, {
      props: { helpText: 'Enter your token' },
    });

    const helpEl = container.querySelector('.text-gray-500, .text-gray-400');
    expect(helpEl).not.toBeNull();
    expect(helpEl.textContent).toBe('Enter your token');
  });
});
