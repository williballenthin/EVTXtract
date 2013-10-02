from progressbar import SimpleProgress, Percentage, Bar, ETA, ProgressBar


class Progress(object):
    """
    An interface to things that track the progress of a long running task.
    """
    def __init__(self, max_):
        super(Progress, self).__init__()
        self._max = max_
        self._current = 0

    def set_current(self, current):
        """
        Set the number of steps that this task has completed.

        @type current: int
        """
        self._current = current

    def set_complete(self):
        """
        Convenience method to set the task as having completed all steps.
        """
        self._current = self._max


class NullProgress(Progress):
    """
    A Progress class that ignores any updates.
    """
    def __init__(self, max_):
        super(NullProgress, self).__init__(max_)

    def set_current(self, current):
        pass


class ProgressBarProgress(Progress):
    def __init__(self, max_):
        super(ProgressBarProgress, self).__init__(max_)

        widgets = ["Progress: ",
                   SimpleProgress(), " ",
                   Percentage(), " ",
                   Bar(marker="=", left="[", right="]"), " ",
                   ETA(), " ", ]
        self._pbar = ProgressBar(widgets=widgets, maxval=self._max)
        self._has_notified_started = False

    def set_current(self, current):
        if not self._has_notified_started:
            self._pbar.start()
            self._has_notified_started = True

        self._pbar.update(current)

    def set_complete(self):
        self._pbar.finish()