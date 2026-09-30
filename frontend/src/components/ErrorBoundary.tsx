import React, { Component, type ErrorInfo, type ReactNode } from 'react';

interface Props {
  children?: ReactNode;
}

interface State {
  hasError: boolean;
  error: Error | null;
  errorInfo: ErrorInfo | null;
}

export class ErrorBoundary extends Component<Props, State> {
  public state: State = {
    hasError: false,
    error: null,
    errorInfo: null
  };

  public static getDerivedStateFromError(error: Error): State {
    return { hasError: true, error, errorInfo: null };
  }

  public componentDidCatch(error: Error, errorInfo: ErrorInfo) {
    console.error('Uncaught error:', error, errorInfo);
    this.setState({ errorInfo });
  }

  public render() {
    if (this.state.hasError) {
      return (
        <div className="p-8 bg-danger/10 border border-danger/50 text-white font-mono">
          <h2 className="text-xl text-danger mb-4">CRITICAL SYSTEM FAILURE</h2>
          <p className="mb-4">The application encountered a fatal error and crashed.</p>
          <pre className="bg-black p-4 text-xs overflow-auto">
            {this.state.error?.toString()}
          </pre>
          <pre className="bg-black/50 mt-4 p-4 text-[10px] overflow-auto text-danger/80">
            {this.state.errorInfo?.componentStack}
          </pre>
          <button 
            className="mt-6 px-4 py-2 bg-danger/20 border border-danger hover:bg-danger text-white transition-colors"
            onClick={() => window.location.reload()}
          >
            REBOOT SYSTEM
          </button>
        </div>
      );
    }

    return this.props.children;
  }
}
